#!/usr/bin/env python3
"""Genuine inactive capability production and independent original-byte replay.

Deterministic fixture keys perform real Ed25519 signing and verification over
independently authored retained proofs. No registry, witness journal, successful
verifier, current root or issuer/database admission is substituted. The producer
and a later independent consumer are distinct invocations with distinct replay
costs; an observation cannot replace either invocation's original evidence.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_capability as capability
from serverware import authority_revocation_capability_production as production
from serverware import authority_revocation_retention as retention
import test_authority_revocation_capability as capability_oracle
import test_authority_revocation_plan as oracle
import test_authority_revocation_retention as record_oracle
import test_authority_revocation_wire as wire_oracle


INPUT_BYTES = ("retained_envelope_bytes", "evaluation_context_bytes", "execution_request_bytes",
               "witness_request_bytes", "witness_receipt_bytes")
PHASES = ("capture", "transport", "key_binding", "witness_verification",
          "retained_verification", "bindings", "signing")


def arguments(fixture):
    """Original independently constructed evidence, never a verified result."""
    supplied = fixture.arguments()
    supplied.pop("envelope_bytes")
    supplied["witness_receipt_bytes"] = oracle.wire(fixture.witness_receipt)
    supplied["signer_private_key"] = fixture.key
    return supplied


def independent_work(fixture):
    """Source-pass oracle from literal fixture graphs, never producer metrics."""
    add, graph = oracle.add, oracle.graph_cost
    same = lambda value: oracle.canonical_comparison(value, value)
    request, receipt = fixture.witness_request, fixture.witness_receipt
    unsigned_request = {name: value for name, value in request.items() if name != "signature"}
    unsigned_receipt = {name: value for name, value in receipt.items() if name != "signature"}
    unsigned_capability = {name: value for name, value in fixture.envelope.items() if name != "signatureBase64Url"}
    material = {name: request[name] for name in ("phase", "operation", "requestDigest", "capabilityId",
        "resultDigest", "predecessorReceiptDigest", "generationSequence", "generationDigest")}
    head = {**unsigned_receipt, "headDigest": None}
    phases = {"capture": graph(capability_oracle.capture_graph(fixture), 1, 1)}
    phases["transport"] = add(*(add(wire_oracle.decoder_units(raw, value), graph(value), (0, 2 * len(raw), 0))
        for raw, value in ((oracle.wire(request), request), (oracle.wire(receipt), receipt),
                          (fixture.execution_bytes, fixture.execution_request))))
    phases["witness_verification"] = add(
        *(same(request[name]) for name in ("configurationDigest", "operationManifestDigest", "generationSequence",
            "generationDigest", "capabilityId", "requestDigest", "deadlineMonotonicNs")),
        oracle.json_digest_cost(capability_oracle.WITNESS_ENVELOPE_DOMAIN, material), same(request["envelopeId"]),
        graph(request), graph(unsigned_request), capability_oracle.signature_work(capability_oracle.REQUEST_SCHEMA, unsigned_request),
        *(same(request[name]) for name in ("envelopeId", "parentEnvelopeId", "phase", "operation", "requestDigest",
            "capabilityId", "resultDigest", "predecessorReceiptDigest", "deadlineMonotonicNs", "generationSequence", "generationDigest")),
        oracle.json_digest_cost(capability_oracle.REQUEST_SCHEMA, request),
        *(same(receipt[name]) for name in ("witnessIdentityDigest", "fence", "canonicalRequestDigest")),
        graph(receipt), graph(unsigned_receipt), oracle.json_digest_cost(capability_oracle.HEAD_DOMAIN, head), same(receipt["headDigest"]),
        graph(unsigned_receipt), capability_oracle.signature_work(capability_oracle.RECEIPT_SCHEMA, unsigned_receipt),
        oracle.json_digest_cost(capability_oracle.RECEIPT_SCHEMA, receipt), same(fixture.witness_receipt_digest))
    replay = record_oracle.independent_record_metrics(fixture.plan)
    phases["retained_verification"] = replay["total"]
    challenge, credential = capability_oracle.original_rows(fixture)
    evidence = fixture.plan.payload["webauthnEvidence"]
    phases["bindings"] = add(same(fixture.execution_request), (1, len(fixture.execution_bytes), 0),
        graph(fixture.plan.payload["mutationPlan"], 4, 4), graph(evidence["challengeId"]), graph(evidence["credentialRecordId"]),
        oracle.json_digest_cost("serverware.policyAuthorityWebAuthnChallengeRow/v1", challenge),
        graph(credential), oracle.utf8_cost(capability_oracle.CREDENTIAL_DOMAIN), (1, 16 + len(oracle.wire(credential)), 0),
        oracle.json_digest_cost(capability_oracle.WEBAUTHN_SCHEMA, capability_oracle.webauthn_receipt(fixture)),
        oracle.json_digest_cost(capability_oracle.CAPABILITY_SCHEMA, fixture.payload))
    # Three actual raw32 key outputs and two 32+32 byte comparisons. No
    # signature/public-key implementation CPU is represented as H/B/N work.
    phases["key_binding"] = (0, 3 * 32 + 2 * 64, 0)
    unsigned_bytes = oracle.wire(unsigned_capability)
    signing_digest = oracle.framed(capability_oracle.SIGNED_SCHEMA, unsigned_bytes)
    phases["signing"] = add(graph(unsigned_capability, 6, 4), graph(fixture.envelope), (0, 566, 0),
        oracle.frame_cost(capability_oracle.SIGNED_SCHEMA, (unsigned_bytes,)), oracle.utf8_cost(signing_digest))
    total = add(*(phases[name] for name in PHASES))
    before_replay = add(*(phases[name] for name in PHASES[:4]))
    retained_peak = add(before_replay, replay["admission"])
    return {**phases, "total": total, "before_signing": add(*(phases[name] for name in PHASES[:-1])),
        "admission": tuple(max(left, right) for left, right in zip(total, retained_peak))}


class _ObservedPrivateKey(Ed25519PrivateKey):
    """Every signing/serialization operation delegates to real fixture keys."""

    def __init__(self, key, callback=lambda: None, *, signing_key=None,
                 public_callback=lambda: None, public_output=None):
        self.key, self.callback, self.calls = key, callback, 0
        self.signing_key = key if signing_key is None else signing_key
        self.public_callback, self.public_output = public_callback, public_output

    def sign(self, data):
        signature = self.signing_key.sign(data)
        self.calls += 1
        self.callback()
        return signature

    def public_key(self):
        actual = self.key.public_key()
        self.public_callback()
        return actual if self.public_output is None else self.public_output

    def private_bytes(self, encoding, format, encryption_algorithm):
        return self.key.private_bytes(encoding, format, encryption_algorithm)

    def private_bytes_raw(self):
        return self.key.private_bytes_raw()

    def __copy__(self):
        return self


class _ObservedPublicBytes(oracle._CallbackPublicKey):
    """Observe or damage the actual raw serialization; never approve a signature."""

    def __init__(self, key, callback=lambda: None, transform=lambda raw: raw):
        super().__init__(key, lambda: None)
        self.serialization_callback, self.transform, self.serializations = callback, transform, 0

    def public_bytes(self, encoding, format):
        actual = self.key.public_bytes(encoding, format)
        self.serializations += 1
        self.serialization_callback()
        return self.transform(actual)


class RevocationCapabilityProducerTests(unittest.TestCase):
    def produce(self, fixture, *, work=None, **changes):
        supplied = arguments(fixture)
        supplied.update(changes)
        if work is None:
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        return production._produce_signed_capability_on_work(work=work, **supplied)

    def assert_original_output(self, actual, fixture):
        self.assertIs(type(actual.envelope_bytes), bytes)
        self.assertIs(type(actual.payload_bytes), bytes)
        self.assertEqual(actual.envelope_bytes, fixture.raw)
        self.assertEqual(actual.payload_bytes, oracle.wire(fixture.payload))
        supplied = arguments(fixture)
        for field in INPUT_BYTES:
            self.assertIs(type(getattr(actual, field)), bytes)
            self.assertEqual(getattr(actual, field), supplied[field], field)
        self.assertEqual(actual.capability_digest,
            oracle.framed(capability_oracle.CAPABILITY_SCHEMA, oracle.wire(fixture.payload)))
        with self.assertRaises(FrozenInstanceError):
            actual.envelope_bytes = b"{}"

    def test_genuine_production_then_independent_consumer_replay_exact_original_bytes(self):
        fixture = capability_oracle.CapabilityFixture()
        expected = independent_work(fixture)
        consumer_work = capability_oracle.independent_capability_work(fixture)
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof, \
                patch.object(retention.plan.semantics, "_derive_revocation_effects",
                    wraps=retention.plan.semantics._derive_revocation_effects) as effects:
            actual = self.produce(fixture, work=work)
            self.assertEqual((replay.call_count, proof.call_count, effects.call_count), (1, 1, 1))
            self.assertIs(replay.call_args.kwargs["work"], work)
            self.assert_original_output(actual, fixture)
            self.assertEqual(oracle.units(work.metrics), expected["total"])
            for phase in PHASES:
                self.assertEqual(oracle.units(getattr(actual.metrics, phase)), expected[phase], phase)
            self.assertEqual((actual.metrics.request_signature_attempts, actual.metrics.witness_signature_attempts,
                actual.metrics.signing_attempts, actual.metrics.signature_verifications), (1, 1, 1, 1))
            self.assertEqual((actual.metrics.total_hashes, actual.metrics.total_input_bytes,
                actual.metrics.total_json_nodes), expected["total"])
            self.assertEqual(expected["total"][0] - expected["retained_verification"][0], 12)
            supplied = fixture.arguments()
            supplied["envelope_bytes"] = actual.envelope_bytes
            consumed = capability._verify_signed_capability_on_work(work=work, **supplied)
            self.assertEqual((replay.call_count, proof.call_count, effects.call_count), (2, 2, 2))
            self.assertTrue(all(call.kwargs["work"] is work for call in replay.call_args_list))
            self.assertEqual(oracle.units(work.metrics), oracle.add(expected["total"], consumer_work["total"]))
        self.assertEqual(consumed.payload, fixture.payload)
        self.assertEqual(consumed.header, capability_oracle.expected_header(fixture))
        self.assertEqual(consumed.record_digest, oracle.framed(capability_oracle.RECORD_SCHEMA,
            oracle.wire(capability_oracle.expected_header(fixture))))
        self.assertEqual(consumed.retained_record.verification.semantics.mutations,
            fixture.plan.semantic.final_mutations)
        self.assertEqual((consumed.metrics.capability_signature_attempts,
            consumed.metrics.request_signature_attempts, consumed.metrics.witness_signature_attempts), (1, 1, 1))

    def test_output_preserves_closed_legacy_semantics_and_preliminary_witness_scope(self):
        fixture = capability_oracle.CapabilityFixture()
        actual = self.produce(fixture)
        self.assert_original_output(actual, fixture)
        self.assertEqual((len(fixture.payload), len(fixture.envelope), len(fixture.witness_request),
                          len(fixture.witness_receipt)), (36, 5, 16, 21))
        self.assertEqual(set(fixture.payload), capability_oracle.PAYLOAD_FIELDS)
        self.assertEqual(set(fixture.envelope), capability_oracle.ENVELOPE_FIELDS)
        receipt = fixture.payload["webauthnReceipt"]
        self.assertEqual(len(receipt), 19)
        _, credential = capability_oracle.original_rows(fixture)
        self.assertEqual(len(credential), 13)
        self.assertEqual(receipt["credentialBindingDigest"], capability_oracle.length_domain_digest(
            capability_oracle.CREDENTIAL_DOMAIN, oracle.wire(credential)))
        self.assertNotEqual(receipt["credentialBindingDigest"], oracle.framed(
            capability_oracle.CREDENTIAL_DOMAIN, oracle.wire(credential)))
        self.assertEqual(fixture.payload["exactRequestBytesDigest"], oracle.sha(fixture.execution_bytes))
        self.assertEqual(fixture.witness_receipt["phase"], "reserve")
        self.assertIsNone(fixture.witness_receipt["resultDigest"])
        self.assertNotIn("retainedRecordDigest", fixture.witness_receipt)
        self.assertNotIn("rootTransitionDigest", fixture.witness_request)
        self.assertEqual(fixture.payload["issuedAtEpochNs"], fixture.plan.reserved_at_epoch_ns)
        self.assertEqual(fixture.payload["issuedMonotonicNs"], fixture.plan.deadline_monotonic_ns
            - (fixture.plan.deadline_epoch_ns - fixture.plan.reserved_at_epoch_ns))

    def test_real_private_public_and_witness_key_mismatches_cannot_trigger_signing(self):
        for changed in ("private", "signer", "witness"):
            fixture = capability_oracle.CapabilityFixture()
            changes = {"private": {"signer_private_key": fixture.other_key},
                "signer": {"signer_public_key": fixture.other_key.public_key()},
                "witness": {"witness_public_key": fixture.other_key.public_key()}}[changed]
            with self.subTest(changed=changed), \
                    patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign, \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(capability.RevocationCapabilityError):
                    self.produce(fixture, **changes)
            self.assertEqual(sign.call_count, 0)
            self.assertEqual(replay.call_count, 0)

    def test_genuinely_signed_same_key_witness_role_is_denied_before_capability_signing(self):
        fixture = capability_oracle.CapabilityFixture()
        fixture.witness_key = fixture.key
        fixture.sign_receipt()
        fixture.rebuild()
        with patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign, \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
            with self.assertRaises(capability.RevocationCapabilityError):
                self.produce(fixture)
        self.assertEqual((sign.call_count, replay.call_count), (0, 0))

    def test_bad_request_and_receipt_signatures_deny_before_retained_replay_and_signing(self):
        for changed in ("request", "receipt"):
            fixture = capability_oracle.CapabilityFixture()
            if changed == "request":
                fixture.sign_request(key=fixture.other_key)
                fixture.witness_receipt["canonicalRequestDigest"] = oracle.framed(
                    capability_oracle.REQUEST_SCHEMA, oracle.wire(fixture.witness_request))
                fixture.sign_receipt()
            else:
                fixture.sign_receipt(key=fixture.other_key)
            fixture.rebuild()
            with self.subTest(changed=changed), \
                    patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign, \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(capability.RevocationCapabilityError):
                    self.produce(fixture)
            self.assertEqual((sign.call_count, replay.call_count), (0, 0))

    def test_genuine_witness_signatures_do_not_waive_independent_reservation_pins(self):
        for changed in ("configuration", "receipt", "head", "generation", "phase"):
            fixture = capability_oracle.CapabilityFixture()
            changes = {}
            if changed == "configuration":
                fixture.witness_request["configurationDigest"] = oracle.sha(b"foreign signed configuration")
                fixture.sign_request()
                fixture.witness_receipt["canonicalRequestDigest"] = oracle.framed(
                    capability_oracle.REQUEST_SCHEMA, oracle.wire(fixture.witness_request))
                fixture.sign_receipt()
            elif changed == "head":
                fixture.witness_receipt["headDigest"] = oracle.sha(b"false head with genuine witness signature")
                fixture.sign_receipt(update_head=False)
            elif changed == "phase":
                fixture.witness_receipt["phase"] = "commit"
                fixture.sign_receipt()
            elif changed == "generation":
                changes["expected_generation_sequence"] = fixture.generation_sequence + 1
            else:
                changes["expected_witness_receipt_digest"] = oracle.sha(b"not the independently accepted receipt")
            fixture.rebuild()
            with self.subTest(changed=changed), \
                    patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign, \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(capability.RevocationCapabilityError):
                    self.produce(fixture, **changes)
            self.assertEqual((sign.call_count, replay.call_count), (0, 0))

    def test_coherently_resigned_false_proof_or_kernel_result_reaches_real_replay_without_signing(self):
        for changed in ("proof", "result"):
            fixture = capability_oracle.CapabilityFixture()
            if changed == "proof":
                bundle = fixture.plan.payload["revocationProofBundle"]
                bundle["inputs"]["beforeProofs"][0]["rootDigest"] = oracle.sha(b"false retained primary proof")
                fixture.plan.payload["rootTransition"]["proofBundleDigest"] = oracle.framed(
                    "serverware.policyAuthorityRevocationProofBundle/v1", oracle.wire(bundle))
            else:
                fixture.plan.payload["expectedResult"] = {"false": "genuinely signed outer documents"}
            fixture.plan.rehash()
            fixture.rebuild()
            with self.subTest(changed=changed), \
                    patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign, \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof, \
                    patch.object(retention.plan.semantics, "_derive_revocation_effects",
                        wraps=retention.plan.semantics._derive_revocation_effects) as effects:
                with self.assertRaises(capability.RevocationCapabilityError):
                    self.produce(fixture)
            self.assertEqual((sign.call_count, replay.call_count, proof.call_count), (0, 1, 1))
            self.assertEqual(effects.call_count, 0 if changed == "proof" else 1)

    def test_every_exact_wrapper_binding_is_checked_after_real_retained_replay_before_signing(self):
        for field in ("schema", "planProtocol", "retainedRecordDigest", "rootTransitionDigest", "typedRequest"):
            fixture = capability_oracle.CapabilityFixture()
            changed = copy.deepcopy(fixture.execution_request)
            changed[field] = ({**changed[field], "requestDigest": oracle.sha(b"foreign request")}
                if field == "typedRequest" else "v3" if field == "planProtocol"
                else "wrong-schema" if field == "schema" else oracle.sha(b"foreign wrapper commitment"))
            with self.subTest(field=field), \
                    patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign, \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
                with self.assertRaises(capability.RevocationCapabilityError):
                    self.produce(fixture, execution_request_bytes=oracle.wire(changed))
            self.assertEqual((sign.call_count, replay.call_count, proof.call_count), (0, 1, 1))

    def test_external_expectations_are_owned_before_real_witness_signature_callbacks(self):
        fixture = capability_oracle.CapabilityFixture()
        supplied = arguments(fixture)
        original = copy.deepcopy(fixture.payload)
        def change():
            supplied["expected_signer_identity"]["measurementDigest"] = oracle.sha(b"late signer identity")
            supplied["retention_expectations"]["expected_request"]["arguments"]["actor_id"] = "late actor"
            supplied["retention_expectations"]["expected_before"]["indexBeforeHeads"][0]["rootDigest"] = oracle.sha(b"late root")
            supplied["retention_expectations"]["expected_planner_identity"]["measurementDigest"] = oracle.sha(b"late planner")
        key = oracle._CallbackPublicKey(fixture.key.public_key(), change)
        supplied["signer_public_key"] = key
        actual = production._produce_signed_capability_on_work(
            work=accounting._ValidationWork(accounting.QueryReadValidationLimits()), **supplied)
        self.assertEqual(key.calls, 2)  # Preliminary request, then the actual paired signing verification.
        self.assertEqual(actual.payload_bytes, oracle.wire(original))
        self.assert_original_output(actual, fixture)

    def test_raw_transport_aliases_and_nonbytes_never_reach_the_signing_side_effect(self):
        fixture = capability_oracle.CapabilityFixture()
        for field in INPUT_BYTES:
            raw = arguments(fixture)[field]
            variants = (b" " + raw, raw.replace(b'"schema":', b'"schema" :', 1),
                raw[:-1] + b',"schema":"duplicate"}', raw.decode("ascii"), bytearray(raw), memoryview(raw), b"")
            for changed in variants:
                with self.subTest(field=field, kind=type(changed).__name__), \
                        patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign:
                    with self.assertRaises(capability.RevocationCapabilityError):
                        self.produce(fixture, **{field: changed})
                self.assertEqual(sign.call_count, 0)

    def test_closed_input_inventory_rejects_success_tokens_and_foreign_work(self):
        fixture = capability_oracle.CapabilityFixture()
        for name in ("payload", "envelope_bytes", "verified_record", "witness_verified", "limits"):
            with self.subTest(extra=name), self.assertRaises(TypeError):
                self.produce(fixture, **{name: {"success": True}})
        for change in ("missing", "extra", "token"):
            supplied = arguments(fixture)
            if change == "missing":
                supplied["retention_expectations"].pop("expected_before")
            elif change == "extra":
                supplied["retention_expectations"]["verified_result"] = {"success": True}
            else:
                supplied["retention_expectations"] = {"recordDigest": fixture.retained_digest, "success": True}
            with self.subTest(change=change), \
                    patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign, \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(capability.RevocationCapabilityError):
                    production._produce_signed_capability_on_work(
                        work=accounting._ValidationWork(accounting.QueryReadValidationLimits()), **supplied)
            self.assertEqual((sign.call_count, replay.call_count), (0, 0))
        for work in (None, object(), accounting.QueryReadValidationLimits()):
            with self.subTest(work=type(work).__name__), \
                    patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign:
                with self.assertRaises(capability.RevocationCapabilityError):
                    production._produce_signed_capability_on_work(work=work, **arguments(fixture))
            self.assertEqual(sign.call_count, 0)
        observed = self.produce(fixture)
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
            with self.assertRaises(capability.RevocationCapabilityError):
                self.produce(fixture, retention_expectations=observed)
        self.assertEqual(replay.call_count, 0)

    def test_exact_preconsumed_and_each_minus_one_keep_one_cumulative_allowance(self):
        fixture = capability_oracle.CapabilityFixture()
        expected = independent_work(fixture)
        for prior in ((0, 0, 0), (3, 31, 7)):
            for dimension in (None, 0, 1, 2):
                ceilings = list(oracle.add(prior, expected["admission"]))
                if dimension is not None:
                    ceilings[dimension] -= 1
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*ceilings))
                work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                entering = work.limits
                with self.subTest(prior=prior, dimension=dimension), \
                        patch.object(retention.plan.retained._PackagingLedger, "__init__",
                            side_effect=AssertionError("replacement outer allowance")):
                    if dimension is None:
                        result = self.produce(fixture, work=work)
                        self.assert_original_output(result, fixture)
                        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["total"]))
                        for phase in PHASES:
                            self.assertEqual(oracle.units(getattr(result.metrics, phase)), expected[phase])
                        self.assertEqual((result.metrics.total_hashes, result.metrics.total_input_bytes,
                            result.metrics.total_json_nodes), oracle.units(work.metrics))
                    else:
                        with self.assertRaises(capability.RevocationCapabilityError):
                            self.produce(fixture, work=work)
                        self.assertTrue(all(start <= spent <= maximum
                            for start, spent, maximum in zip(prior, oracle.units(work.metrics), ceilings)))
                self.assertIs(work.limits, entering)
                self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_repeated_production_and_later_consumer_replay_never_cache_success(self):
        fixture, prior = capability_oracle.CapabilityFixture(), (2, 17, 5)
        expected = independent_work(fixture)
        consumer = capability_oracle.independent_capability_work(fixture)
        # One ceiling covers both producer invocations and the separate real
        # consumer; each retained replay must retain its own compact hold peak.
        first_peak = oracle.add(prior, expected["admission"])
        second_peak = oracle.add(prior, expected["total"], expected["admission"])
        consumer_peak = oracle.add(prior, expected["total"], expected["total"], consumer["admission"])
        ceilings = tuple(max(values) for values in zip(first_peak, second_peak, consumer_peak))
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*ceilings))
        work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        entering, outputs = work.limits, []
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            for count in (1, 2):
                output = self.produce(fixture, work=work)
                outputs.append(output)
                self.assert_original_output(output, fixture)
                self.assertEqual(oracle.units(work.metrics), oracle.add(prior, tuple(count * value for value in expected["total"])))
                self.assertEqual((replay.call_count, proof.call_count), (count, count))
            supplied = fixture.arguments()
            supplied["envelope_bytes"] = outputs[1].envelope_bytes
            consumed = capability._verify_signed_capability_on_work(work=work, **supplied)
            self.assertEqual((replay.call_count, proof.call_count), (3, 3))
            self.assertTrue(all(call.kwargs["work"] is work for call in replay.call_args_list))
        self.assertIsNot(outputs[0], outputs[1])
        self.assertEqual(outputs[0].envelope_bytes, outputs[1].envelope_bytes)
        self.assertEqual(consumed.header, capability_oracle.expected_header(fixture))
        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["total"], expected["total"], consumer["total"]))
        self.assertIs(work.limits, entering)
        self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_complete_final_signing_reservation_precedes_all_three_output_encoders(self):
        fixture, prior = capability_oracle.CapabilityFixture(), (2, 19, 3)
        expected = independent_work(fixture)
        original_sign_wire = production._sign_wire
        original_encode = capability.plan.core.canonical_bytes
        for dimension in (None, 0, 1, 2):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(
                *oracle.add(prior, expected["admission"])))
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            entering, encoders, reached = work.limits, [], []
            extra = [peak - total for peak, total in zip(expected["admission"], expected["total"])]
            if dimension is not None:
                extra[dimension] += 1
            def final_signing(*args):
                self.assertIs(args[-1], work)
                self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["before_signing"]))
                reached.append(True)
                # Consume only real remaining allowance after genuine replay.
                # No counter assignment, ceiling replacement or new meter is
                # used to isolate this final reservation from the earlier peak.
                work.charge(hashes=extra[0], input_bytes=extra[1], json_nodes=extra[2])
                return original_sign_wire(*args)
            def encode(value):
                if type(value) is dict and value.get("schema") == capability_oracle.SIGNED_SCHEMA:
                    encoders.append(tuple(sorted(value)))
                return original_encode(value)
            with self.subTest(dimension=dimension), \
                    patch.object(production, "_sign_wire", side_effect=final_signing), \
                    patch.object(capability.plan.core, "canonical_bytes", side_effect=encode), \
                    patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign, \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
                if dimension is None:
                    actual = self.produce(fixture, work=work)
                    self.assert_original_output(actual, fixture)
                    self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["total"], tuple(extra)))
                else:
                    with self.assertRaises(capability.RevocationCapabilityError):
                        self.produce(fixture, work=work)
            self.assertEqual((reached, replay.call_count, proof.call_count), ([True], 1, 1))
            unsigned_fields = tuple(sorted(capability_oracle.ENVELOPE_FIELDS - {"signatureBase64Url"}))
            self.assertEqual(encoders, [unsigned_fields, unsigned_fields, tuple(sorted(capability_oracle.ENVELOPE_FIELDS))]
                if dimension is None else [])
            self.assertEqual(sign.call_count, 1 if dimension is None else 0)
            self.assertIs(work.limits, entering)

    def test_actual_signer_output_must_verify_with_its_previously_matched_public_pin(self):
        fixture = capability_oracle.CapabilityFixture()
        # Public derivation genuinely matches first, then a real different
        # Ed25519 key signs. The actual paired verification must reject it.
        private = _ObservedPrivateKey(fixture.key, signing_key=fixture.other_key)
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign:
            with self.assertRaisesRegex(capability.RevocationCapabilityError, "signature differs from its independent public pin"):
                self.produce(fixture, signer_private_key=private)
        self.assertEqual((private.calls, sign.call_count, replay.call_count), (1, 1, 1))

    def test_real_signature_callbacks_cannot_spend_refund_retype_or_replace_work(self):
        for phase in ("request", "witness", "private_sign", "paired_verify"):
            for change in ("spend", "refund", "float", "limits"):
                fixture = capability_oracle.CapabilityFixture()
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
                work.charge(hashes=2, input_bytes=13, json_nodes=3)
                callbacks, changed = [], []
                def callback():
                    callbacks.append(work.metrics)
                    if phase == "paired_verify" and len(callbacks) == 1:
                        return
                    if change == "spend":
                        work.charge(hashes=1)
                    elif change == "refund":
                        work.hash_work -= 1
                    elif change == "float":
                        work.hash_work = float(work.hash_work)
                    else:
                        work.limits = accounting.QueryReadValidationLimits()
                    changed.append((work.hash_work, work.input_bytes, work.json_nodes, work.limits))
                if phase == "private_sign":
                    observed_key = _ObservedPrivateKey(fixture.key, callback)
                    changes = {"signer_private_key": observed_key}
                else:
                    observed_key = oracle._CallbackPublicKey(
                        (fixture.witness_key if phase == "witness" else fixture.key).public_key(), callback)
                    changes = {"witness_public_key" if phase == "witness" else "signer_public_key": observed_key}
                with self.subTest(phase=phase, change=change), \
                        patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign, \
                        patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                    with self.assertRaises(capability.RevocationCapabilityError):
                        self.produce(fixture, work=work, **changes)
                self.assertEqual(observed_key.calls, 2 if phase == "paired_verify" else 1)
                self.assertEqual(len(changed), 1)
                self.assertEqual((sign.call_count, replay.call_count), (1, 1)
                    if phase in {"private_sign", "paired_verify"} else (0, 0))
                observed = changed[0]
                self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), observed[:3])
                self.assertIs(type(work.hash_work), float if change == "float" else int)
                self.assertIs(work.limits, observed[3])

    def test_real_key_derivation_and_raw32_callbacks_are_guarded_before_witness_or_replay(self):
        fixture = capability_oracle.CapabilityFixture()
        for phase in ("derive", "derived", "signer", "witness"):
            for change in ("spend", "refund", "float", "limits"):
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
                work.charge(hashes=2, input_bytes=13, json_nodes=3)
                changed = []
                def callback():
                    if change == "spend":
                        work.charge(hashes=1)
                    elif change == "refund":
                        work.hash_work -= 1
                    elif change == "float":
                        work.hash_work = float(work.hash_work)
                    else:
                        work.limits = accounting.QueryReadValidationLimits()
                    changed.append((work.hash_work, work.input_bytes, work.json_nodes, work.limits))
                if phase == "derive":
                    changes = {"signer_private_key": _ObservedPrivateKey(fixture.key, public_callback=callback)}
                else:
                    key = _ObservedPublicBytes(
                        (fixture.witness_key if phase == "witness" else fixture.key).public_key(), callback)
                    changes = ({"signer_private_key": _ObservedPrivateKey(fixture.key, public_output=key)}
                        if phase == "derived" else {"witness_public_key" if phase == "witness" else "signer_public_key": key})
                with self.subTest(phase=phase, change=change), \
                        patch.object(capability, "_witness", wraps=capability._witness) as witness, \
                        patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                        patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign:
                    with self.assertRaises(capability.RevocationCapabilityError):
                        self.produce(fixture, work=work, **changes)
                self.assertEqual((witness.call_count, replay.call_count, sign.call_count), (0, 0, 0))
                self.assertEqual(len(changed), 1)
                self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), changed[0][:3])
                self.assertIs(type(work.hash_work), float if change == "float" else int)
                self.assertIs(work.limits, changed[0][3])
        for phase in ("derived", "signer", "witness"):
            for transform in (lambda raw: raw[:-1], lambda raw: raw + b"x", bytearray, memoryview):
                key = _ObservedPublicBytes(
                    (fixture.witness_key if phase == "witness" else fixture.key).public_key(), transform=transform)
                changes = ({"signer_private_key": _ObservedPrivateKey(fixture.key, public_output=key)}
                    if phase == "derived" else {"witness_public_key" if phase == "witness" else "signer_public_key": key})
                with self.subTest(phase=phase, transform=transform), \
                        patch.object(capability, "_witness", wraps=capability._witness) as witness, \
                        patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                        patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign:
                    with self.assertRaisesRegex(capability.RevocationCapabilityError, "signing keys are not exact raw32"):
                        self.produce(fixture, **changes)
                self.assertEqual((key.serializations, key.calls), (1, 0))
                self.assertEqual((witness.call_count, replay.call_count, sign.call_count), (0, 0, 0))

    def test_postsign_graph_replacement_cannot_publish_bytes_inconsistent_with_signature(self):
        fixture = capability_oracle.CapabilityFixture()
        original_sign_wire = production._sign_wire
        captured = []
        def signing(payload, identity, private_key, public_key, work):
            captured.append(payload)
            return original_sign_wire(payload, identity, private_key, public_key, work)
        def change():
            self.assertEqual(len(captured), 1)
            # Equal wire length/node count forces the genuine canonical byte
            # comparison, not only the post-sign size/type checks, to deny.
            captured[0]["expectedResultDigest"] = oracle.sha(b"late unsigned result")
        private = _ObservedPrivateKey(fixture.key, change)
        with patch.object(production, "_sign_wire", side_effect=signing), \
                patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
            with self.assertRaisesRegex(capability.RevocationCapabilityError, "unsigned graph changed during signing"):
                self.produce(fixture, signer_private_key=private)
        self.assertEqual((private.calls, replay.call_count), (1, 1))

    def test_receipt_transport_and_final_output_local_bounds_are_not_extra_work_allowances(self):
        fixture = capability_oracle.CapabilityFixture()
        for constant, exact, before_replay in (
                ("MAX_WITNESS_RECEIPT_BYTES", len(oracle.wire(fixture.witness_receipt)), True),
                ("MAX_CAPABILITY_BYTES", len(fixture.raw), False)):
            for difference in (0, 1):
                with self.subTest(constant=constant, difference=difference), \
                        patch.object(production, constant, exact - difference), \
                        patch.object(production, "_sign_and_verify", wraps=production._sign_and_verify) as sign, \
                        patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                    if difference:
                        with self.assertRaises(capability.RevocationCapabilityError):
                            self.produce(fixture)
                    else:
                        self.assert_original_output(self.produce(fixture), fixture)
                self.assertEqual(sign.call_count, 0 if difference else 1)
                self.assertEqual(replay.call_count, 0 if difference and before_replay else 1)


if __name__ == "__main__":
    unittest.main()
