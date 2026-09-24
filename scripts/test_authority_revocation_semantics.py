#!/usr/bin/env python3
"""Genuine inactive revocation composition over independent complete proofs.

All signatures, request commitments, range/primary proofs, kernel effects and
capacity validation use real source bodies. Test pins, clocks, capability and
expected-before roots remain synthetic admission inputs, not currentness or
physical-authenticator authority. Authored source-only; no execution claimed.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_audit_capacity as capacity
from serverware import authority_request_commitment as commitment
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_proof_bundle as retained
from serverware import authority_revocation_read_write as mixed
from serverware import authority_revocation_semantics as semantics
from serverware import authority_transition_webauthn as candidate
from serverware import authority_webauthn_assertion as assertion
from authority_revocation_semantics_fixture import SemanticFixture, OPERATION, wire, framed
import test_authority_audit_capacity_work as capacity_oracle
import test_authority_revocation_proof_bundle as retained_oracle
import test_authority_typed_request_work as request_oracle
import test_webauthn_assertion_work as receipt_oracle
import test_webauthn_revocation_work as kernel_oracle


PHASES = ("capture", "request_binding", "receipt", "context_binding", "proof", "kernel",
          "capacity", "mutation_binding")


def units(value):
    return value.hash_work, value.input_bytes, value.json_nodes


def forged(value, **changes):
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(value, field.name)))
    return result


def add(*triples):
    return tuple(sum(value[index] for value in triples) for index in range(3))


def graph_cost(value, byte_passes=2, node_passes=2):
    return 0, byte_passes * len(wire(value)), node_passes * kernel_oracle.nodes(value)


def scalar_comparison(left, right):
    return add(graph_cost(left), graph_cost(right))


def canonical_comparison(left, right):
    # Real compact encoding on each side followed by both raw byte scans.
    return add(graph_cost(left, 3, 2), graph_cost(right, 3, 2))


def capture_document(fixture):
    supplied = fixture.inputs()
    return {"bundle": supplied["bundle"], "transition": supplied["transition"],
        "request": supplied["request"], "evidence": supplied["evidence"],
        "verifierIdentity": supplied["verifier_identity"], "capabilityId": supplied["capability_id"],
        "databaseCutoffUs": fixture.cutoff_us, "nowEpochNs": supplied["now_epoch_ns"],
        "deadlineEpochNs": supplied["deadline_epoch_ns"], "maximumAgeNs": supplied["maximum_age_ns"],
        "expectedBefore": supplied["expected_before"]}


def independent_metrics(fixture):
    """Full semantic work from literal graph sizes and reviewed pass oracles.

    No production metric, returned observation or limit is an expected input.
    Old retained ownership is excluded: this entrypoint owns the expanded raw
    graph exactly once, before receipt/request and genuine proof verification.
    """
    result = {"capture": graph_cost(capture_document(fixture), 1, 1)}
    request = fixture.request
    binding = [request_oracle.expected_work(request).total]
    binding.extend(scalar_comparison(left, right) for left, right in (
        (fixture.request_digest, request["requestDigest"]),
        (fixture.request_digest, fixture.bundle["inputs"]["requestDigest"]),
        (fixture.operation_id, request["operationId"])))
    binding.append((1, 2 * (len(OPERATION.encode("utf-8")) + len(fixture.request_digest.encode("utf-8"))), 4))
    binding.append(canonical_comparison(request["arguments"], fixture.bundle["inputs"]["arguments"]))
    result["request_binding"] = add(*binding)
    result["receipt"] = receipt_oracle.expected_work(fixture.receipt).total
    context = [scalar_comparison(fixture.cutoff_us, fixture.cutoff_us)]
    context.extend(scalar_comparison(fixture.receipt.evidence[field], fixture.assertion_binding[field])
        for field in ("credentialRecordId", "challengeId"))
    for expected, raw in (("businessBeforeRoots", "businessBeforeRoots"),
                          ("authorizationBeforeRoots", "authorizationBeforeRoots"),
                          ("indexBeforeHeads", "countedBeforeHeads")):
        context.append(canonical_comparison(fixture.expected_before[expected], fixture.bundle["inputs"][raw]))
    result["context_binding"] = add(*context)
    packaging = retained_oracle.expected_packaging(fixture, replay=True)
    triples = lambda mapping: tuple(mapping[name] for name in ("hash_work", "input_bytes", "json_nodes"))
    result["proof"] = add(triples(packaging["claim_encoding"]), triples(packaging["bundle_encoding"]),
        *(triples(value) for value in packaging["verification"].values()), triples(packaging["finalization"]))
    result["kernel"] = kernel_oracle.expected_work(fixture.kernel_fixture, fixture.kernel_expected).total
    result["capacity"] = capacity_oracle.expected_work(fixture.context, fixture.kernel_expected["mutations"]).tuple()
    # Two copy/sort/tuple passes per side, then two real canonical encodings.
    result["mutation_binding"] = add(graph_cost(fixture.final_mutations, 8, 8),
        canonical_comparison(fixture.final_mutations, fixture.read_write.mutations))
    result["total"] = add(*(result[name] for name in PHASES))
    proof_final = triples(packaging["finalization"])
    proof_prefix = tuple(result["proof"][index] - proof_final[index] for index in range(3))
    before_release = add(*(result[name] for name in PHASES[:4]), proof_prefix)
    result["retained_peak"] = add(before_release, (1, 262_144, 2048))
    result["admission"] = tuple(max(result["retained_peak"][index], result["total"][index])
        for index in range(3))
    result["proof_snapshot"] = add(*(result[name] for name in PHASES[:5]))
    return result


class RevocationSemanticsTests(unittest.TestCase):
    def verify(self, fixture, **changes):
        inputs = fixture.inputs()
        inputs.update(changes)
        return semantics.verify_revocation_semantics(**inputs)

    def assert_complete(self, fixture, actual):
        self.assertEqual(actual.kernel.mutations, fixture.kernel_expected["mutations"])
        self.assertEqual(actual.kernel.result, fixture.kernel_expected["result"])
        self.assertEqual(actual.kernel.work_units, fixture.kernel_expected["work_units"])
        self.assertEqual(actual.mutations, fixture.final_mutations)
        self.assertEqual(actual.work_units, fixture.work_units)
        self.assertEqual(actual.proof.bundle_bytes, wire(fixture.bundle))
        self.assertEqual(actual.proof.transition_bytes, wire(fixture.transition))
        self.assertEqual(actual.proof.bundle_digest,
            retained_oracle.digest(retained_oracle.BUNDLE_SCHEMA, wire(fixture.bundle)))
        self.assertEqual(actual.proof.transition_digest,
            retained_oracle.digest(retained_oracle.TRANSITION_SCHEMA, wire(fixture.transition)))
        for root_class in ("business", "authorization"):
            expected = tuple(fixture.read_write.after_trees[item.table].root
                for item in fixture.read_write.read.contracts if item.root_class == root_class)
            self.assertEqual(getattr(actual.proof.primary, root_class + "_after_roots"), expected)
        self.assertEqual(actual.metrics.signature_attempts, 1)
        self.assertNotIn("receipt", fixture.transition["metrics"])
        self.assertNotIn("kernel", fixture.transition["metrics"])

    def test_real_full_effects_receipt_and_independent_before_after_tree_commitments(self):
        fixture = SemanticFixture()
        supplied = fixture.inputs()
        supplied["bundle"] = json.loads(wire(fixture.bundle))
        supplied["transition"] = json.loads(wire(fixture.transition))
        actual = semantics.verify_revocation_semantics(**supplied)
        self.assert_complete(fixture, actual)
        self.assertEqual(len(fixture.kernel_expected["mutations"]), 9)
        self.assertEqual(len(actual.mutations), 10)
        self.assertEqual(len(fixture.expected_before["indexBeforeHeads"]), 8)
        counter = next(item for item in actual.mutations
            if item["table"] == "policy_authority_bounded_aggregate_states")
        self.assertEqual((counter["row"]["revision"], counter["row"]["live_count"],
                          counter["row"]["next_sequence"]), (8, 2, 21))
        self.assertTrue(any(item["operation"] == "INSERT" for item in actual.mutations))
        self.assertEqual(request_oracle.expected_digest(fixture.request), fixture.request_digest)

    def test_same_separate_signer_empty_roles_no_audit_and_global_registration(self):
        for options in ({"separate_signer": True}, {"approval": False, "include_audit": False},
                        {"approval": False}, {"pending_count": 2}):
            fixture = SemanticFixture(**options)
            with self.subTest(options=options):
                actual = self.verify(fixture)
                self.assert_complete(fixture, actual)
                changed = next(item for item in actual.mutations
                    if item["table"] == "webauthn_challenges" and item["key"] == {"id": "future"})
                self.assertEqual(changed["expectedRow"]["user_id"], "other-user")
                self.assertEqual(changed["row"]["used_at"], fixture.database_now.isoformat())
                if not options.get("approval", True):
                    empty = next(record for document, record in zip(fixture.documents, fixture.query_reads)
                        if document.get("role") == "approvals")
                    self.assertEqual((empty.addresses, empty.returned_row_count), ((), 0))
                if not options.get("approval", True) and not options.get("include_audit", True):
                    self.assertFalse(any(item["table"] in ("metadata_audit_outbox",
                        "policy_authority_bounded_aggregate_states") for item in actual.mutations))
                if options.get("separate_signer"):
                    credentials = {item["key"]["id"]: item["row"] for item in actual.mutations
                        if item["table"] == "webauthn_credentials"}
                    self.assertEqual(credentials[fixture.values["record_id"]]["sign_count"], 2)
                    self.assertEqual(credentials[fixture.signer_id]["sign_count"], 3)

    def test_one_owned_capture_real_private_phases_and_same_shared_semantic_ledger(self):
        fixture = SemanticFixture()
        seen = {name: [] for name in ("capture", "request", "receipt", "proof", "mixed", "kernel", "capacity", "validator")}
        real_visit = semantics.query_batch._JSONCapture.visit
        real_request, real_receipt = commitment._typed_request_digest, assertion._verify_revoke_assertion_evidence
        real_proof, real_mixed = retained._compute_and_package, mixed._verify
        real_kernel, real_capacity = candidate.WebAuthnCredentialRevokeKernel._transition, capacity._finalize_capacity
        real_validator = capacity._validate_capacity_transition

        def visit(copier, value, depth=0, ancestors=frozenset()):
            if copier.retain and not ancestors:
                seen["capture"].append((copier.ledger, depth))
            return real_visit(copier, value, depth, ancestors)

        def request(value, **kwargs):
            seen["request"].append(kwargs["work"])
            return real_request(value, **kwargs)

        def receipt(*args, **kwargs):
            result = real_receipt(*args, **kwargs)
            seen["receipt"].append((kwargs["work"], result))
            return result

        def proof(**kwargs):
            result = real_proof(**kwargs)
            seen["proof"].append((kwargs["ledger"], result))
            return result

        def verify_mixed(*args, **kwargs):
            result = real_mixed(*args, **kwargs)
            seen["mixed"].append(result)
            return result

        def kernel(instance, context, **kwargs):
            result = real_kernel(instance, context, **kwargs)
            seen["kernel"].append((context, kwargs["work"], result))
            return result

        def finalize(context, mutations, **kwargs):
            result = real_capacity(context, mutations, **kwargs)
            seen["capacity"].append((context, mutations, kwargs["work"], result))
            return result

        def validate(**kwargs):
            seen["validator"].append(kwargs["work"])
            return real_validator(**kwargs)

        with patch.object(semantics.query_batch._JSONCapture, "visit", visit), \
                patch.object(commitment, "_typed_request_digest", request), \
                patch.object(assertion, "_verify_revoke_assertion_evidence", receipt), \
                patch.object(retained, "_compute_and_package", proof), patch.object(mixed, "_verify", verify_mixed), \
                patch.object(candidate.WebAuthnCredentialRevokeKernel, "_transition", kernel), \
                patch.object(capacity, "_finalize_capacity", finalize), \
                patch.object(capacity, "_validate_capacity_transition", validate), \
                patch.object(retained, "verify_revocation_proof_bundle", side_effect=AssertionError("public budget reset")), \
                patch.object(mixed, "verify_revocation_read_write_inputs", side_effect=AssertionError("second ownership")), \
                patch.object(candidate.WebAuthnCredentialRevokeKernel, "transition", side_effect=AssertionError("unmetered kernel")):
            actual = self.verify(fixture)
        self.assert_complete(fixture, actual)
        self.assertTrue(all(len(value) == 1 for value in seen.values()))
        ledger = seen["capture"][0][0]
        self.assertEqual(seen["capture"][0][1], -1)
        self.assertIs(seen["request"][0], ledger.work)
        self.assertIs(seen["receipt"][0][0].shared, ledger.work)
        self.assertIs(seen["proof"][0][0], ledger)
        self.assertIs(seen["proof"][0][1][1], seen["mixed"][0])
        context, work, result = seen["kernel"][0]
        self.assertIs(work, ledger.work)
        self.assertIs(result, actual.kernel)
        self.assertIs(context.selected_rows, seen["mixed"][0].selected_rows)
        self.assertIs(context.query_reads, seen["mixed"][0].query_reads)
        self.assertIs(context.verified_webauthn_evidence, seen["receipt"][0][1])
        self.assertIs(seen["capacity"][0][0], context)
        self.assertIs(seen["capacity"][0][1], actual.kernel.mutations)
        self.assertIs(seen["capacity"][0][2], ledger.work)
        self.assertIs(seen["validator"][0], ledger.work)
        self.assertIs(actual.proof.primary, seen["mixed"][0].write.primary)

    def test_every_raw_graph_is_owned_before_the_first_real_request_hash(self):
        fixture = SemanticFixture(pending_count=2)
        inputs = fixture.inputs()
        real_hash = hashlib.sha256
        calls = []

        def observe(*args, **kwargs):
            if not calls:
                inputs["request"]["arguments"]["reason"] = "caller changed after capture"
                inputs["evidence"]["counter"] = 999
                inputs["verifier_identity"]["measurementDigest"] = "sha256:" + "f" * 64
                inputs["expected_before"]["businessBeforeRoots"][0]["rootRevision"] += 1
                raw = inputs["bundle"]["inputs"]
                raw["selectedRows"][0]["present"] = not raw["selectedRows"][0]["present"]
                raw["mutations"][-1]["row"]["callerMutation"] = True
                raw["queryFrontiers"][-1]["frontier"].clear()
                raw["beforeProofs"].clear()
                raw["queryReads"][-1]["declaredQueryJson"] = "{}"
                inputs["transition"]["indexAfterHeads"][0]["leafCount"] += 1
            calls.append(args)
            return real_hash(*args, **kwargs)

        with patch.object(hashlib, "sha256", observe):
            actual = semantics.verify_revocation_semantics(**inputs)
        self.assert_complete(fixture, actual)
        self.assertGreater(len(calls), 8)
        # The genuine planner frame starts an empty SHA object, then updates
        # the domain and lengths; the observer still runs at its first hash.
        self.assertEqual(calls[0], ())

    def test_full_request_digest_operation_handler_and_arguments_are_bound(self):
        fixture = SemanticFixture(approval=False, include_audit=False)
        variants = []
        for field, value in (("requestDigest", "sha256:" + "0" * 64),
                             ("operationId", "sha256:" + "0" * 64),
                             ("handler", "wrong_handler"),
                             ("operationManifestDigest", "sha256:" + "0" * 64)):
            request = copy.deepcopy(fixture.request)
            request[field] = value
            variants.append(request)
        changed = request_oracle.request_fixture(values={**fixture.values, "reason": "different intent"})
        variants.append(changed)
        for request in variants:
            with self.subTest(request=request), patch.object(mixed, "_verify", wraps=mixed._verify) as proof, \
                    self.assertRaises(semantics.RevocationSemanticsError):
                self.verify(fixture, request=request)
            self.assertEqual(proof.call_count, 0)

    def test_pinned_receipt_signature_context_capability_and_fresh_time_are_genuine(self):
        fixture = SemanticFixture()
        bad_signature = fixture.receipt.sign(fixture.receipt.evidence, key=fixture.receipt.other_key)
        bad_identity = {**fixture.receipt.identity, "measurementDigest": "sha256:" + "0" * 64}
        cases = ({"evidence": bad_signature}, {"verifier_public_key": fixture.receipt.other_key.public_key()},
            {"verifier_identity": bad_identity}, {"capability_id": "sha256:" + "0" * 64},
            {"now_epoch_ns": fixture.receipt.now + 61_000_000_000},
            {"deadline_epoch_ns": fixture.receipt.now - 1}, {"maximum_age_ns": 60_000_000_000})
        for changes in cases:
            with self.subTest(changes=tuple(changes)), patch.object(mixed, "_verify", wraps=mixed._verify) as proof, \
                    self.assertRaises(semantics.RevocationSemanticsError):
                self.verify(fixture, **changes)
            self.assertEqual(proof.call_count, 0)
        with patch.object(assertion, "_verify_receipt_signature", wraps=assertion._verify_receipt_signature) as signature:
            self.assert_complete(fixture, self.verify(fixture))
        self.assertEqual(signature.call_count, 1)

    def test_signed_assertion_ids_must_equal_the_captured_query_binding(self):
        fixture = SemanticFixture()
        for field in ("credentialRecordId", "challengeId"):
            evidence = fixture.receipt.sign({**fixture.receipt.evidence, field: "other-valid-id"})
            with self.subTest(field=field), \
                    patch.object(assertion, "_verify_receipt_signature", wraps=assertion._verify_receipt_signature) as signature, \
                    patch.object(mixed, "_verify", wraps=mixed._verify) as proof, \
                    self.assertRaises(semantics.RevocationSemanticsError):
                self.verify(fixture, evidence=evidence)
            self.assertEqual(signature.call_count, 1)
            self.assertEqual(proof.call_count, 0)
        # A genuinely signed receipt with the correct lookup IDs but the wrong
        # challenge-row commitment passes receipt verification, then the real
        # kernel must bind it to the independently authenticated stored row.
        evidence = fixture.receipt.sign({**fixture.receipt.evidence,
            "challengeDigest": "sha256:" + "0" * 64})
        with patch.object(mixed, "_verify", wraps=mixed._verify) as proof, \
                patch.object(capacity, "_finalize_capacity", wraps=capacity._finalize_capacity) as finalizer, \
                self.assertRaises(semantics.RevocationSemanticsError):
            self.verify(fixture, evidence=evidence)
        self.assertEqual((proof.call_count, finalizer.call_count), (1, 0))

    def test_all_independent_before_vectors_and_exact_database_instant_are_bound(self):
        fixture = SemanticFixture()
        for field in fixture.expected_before:
            value = copy.deepcopy(fixture.expected_before)
            if value[field]:
                revision = "indexRevision" if field == "indexBeforeHeads" else "rootRevision"
                value[field][0][revision] += 1
            else:
                value[field] = [{"table": "not_authorized", "rootRevision": 1,
                    "rootDigest": "sha256:" + "0" * 64, "leafCount": 0}]
            with self.subTest(field=field), patch.object(mixed, "_verify", wraps=mixed._verify) as proof, \
                    self.assertRaises(semantics.RevocationSemanticsError):
                self.verify(fixture, expected_before=value)
            self.assertEqual(proof.call_count, 0)
        for instant in (fixture.database_now + timedelta(microseconds=1),
                        fixture.database_now.replace(tzinfo=None),
                        fixture.database_now.astimezone(timezone(timedelta(hours=1)))):
            with self.subTest(instant=instant), patch.object(mixed, "_verify", wraps=mixed._verify) as proof, \
                    self.assertRaises(semantics.RevocationSemanticsError):
                self.verify(fixture, database_now=instant)
            self.assertEqual(proof.call_count, 0)

    def test_genuine_proofs_for_wrong_full_effects_fail_only_after_kernel_and_capacity(self):
        fixture = SemanticFixture()
        changed = copy.deepcopy(fixture.final_mutations)
        target = next(item for item in changed if item["table"] == "webauthn_credentials")
        target["row"]["revocation_reason"] = "not the committed request reason"
        fixture.rebuild_claim(changed)
        with patch.object(retained, "_compute_and_package", wraps=retained._compute_and_package) as proof, \
                patch.object(capacity, "_finalize_capacity", wraps=capacity._finalize_capacity) as finalizer, \
                self.assertRaisesRegex(semantics.RevocationSemanticsError, "proved mutations differ"):
            self.verify(fixture)
        self.assertEqual((proof.call_count, finalizer.call_count), (1, 1))

    def test_counter_omission_or_false_counter_effect_can_have_valid_proofs_but_not_semantics(self):
        for omit in (True, False):
            fixture = SemanticFixture()
            changed = copy.deepcopy(fixture.final_mutations)
            if omit:
                changed = tuple(item for item in changed
                    if item["table"] != "policy_authority_bounded_aggregate_states")
            else:
                counter = next(item for item in changed
                    if item["table"] == "policy_authority_bounded_aggregate_states")
                counter["row"]["next_sequence"] += 1
            fixture.rebuild_claim(changed)
            with self.subTest(omit=omit), \
                    patch.object(capacity, "_finalize_capacity", wraps=capacity._finalize_capacity) as finalizer, \
                    self.assertRaisesRegex(semantics.RevocationSemanticsError, "proved mutations differ"):
                self.verify(fixture)
            self.assertEqual(finalizer.call_count, 1)

    def test_full_row_canonical_comparison_distinguishes_boolean_integer_aliases(self):
        fixture = SemanticFixture()
        changed = copy.deepcopy(fixture.final_mutations)
        target = next(item for item in changed if item["table"] == "webauthn_credentials")
        target["row"]["metadata"]["flags"][0] = 1
        self.assertEqual(changed, fixture.final_mutations)  # Python equality is insufficient.
        self.assertNotEqual(wire(changed), wire(fixture.final_mutations))
        fixture.rebuild_claim(changed)
        with patch.object(capacity, "_finalize_capacity", wraps=capacity._finalize_capacity) as finalizer, \
                self.assertRaisesRegex(semantics.RevocationSemanticsError, "proved mutations differ"):
            self.verify(fixture)
        self.assertEqual(finalizer.call_count, 1)

    def test_permuted_proved_inventory_uses_the_actual_planner_order_on_both_sides(self):
        fixture = SemanticFixture(separate_signer=True)
        fixture.rebuild_claim(tuple(reversed(fixture.final_mutations)))
        self.assertNotEqual(fixture.read_write.mutations, fixture.final_mutations)
        self.assert_complete(fixture, self.verify(fixture))

    def test_real_primary_and_counted_proof_corruption_stops_before_kernel(self):
        for area in ("row", "query", "write"):
            fixture = SemanticFixture()
            bundle = copy.deepcopy(fixture.bundle)
            raw = bundle["inputs"]
            if area == "row":
                selected = next(item for item in raw["selectedRows"] if item["present"]
                    and item["table"] == "webauthn_credentials")
                selected["row"]["uncommitted"] = True
            elif area == "query":
                frontier = next(item["frontier"] for item in raw["queryFrontiers"]
                    if any(value["kind"] == "leaf" for value in item["frontier"]))
                next(item for item in frontier if item["kind"] == "leaf")["primaryRowDigest"] = "sha256:" + "0" * 64
            else:
                frontier = next(item["frontier"] for item in raw["writeFrontiers"]
                    if any(value["kind"] == "leaf" for value in item["frontier"]))
                next(item for item in frontier if item["kind"] == "leaf")["primaryRowDigest"] = "sha256:" + "0" * 64
            claim = retained_oracle.rebound_claim(bundle, fixture.transition)
            with self.subTest(area=area), patch.object(mixed, "_verify", wraps=mixed._verify) as proof, \
                    patch.object(candidate.WebAuthnCredentialRevokeKernel, "_transition",
                        side_effect=AssertionError("corrupt proof reached the kernel")) as kernel, \
                    self.assertRaises(semantics.RevocationSemanticsError):
                self.verify(fixture, bundle=bundle, transition=claim)
            self.assertEqual(proof.call_count, 1)
            kernel.assert_not_called()  # Never supplies successful semantics.

    def test_invalid_capacity_baseline_is_not_repaired_by_valid_membership_proofs(self):
        fixture = SemanticFixture()
        before = fixture.rows["policy_authority_bounded_aggregate_states"][0]
        before["state_json"] = "{}"
        fixture.rebuild_claim(fixture.final_mutations)
        real_kernel = candidate.WebAuthnCredentialRevokeKernel._transition
        kernels = []

        def kernel(instance, context, **kwargs):
            result = real_kernel(instance, context, **kwargs)
            kernels.append(result)
            return result

        with patch.object(candidate.WebAuthnCredentialRevokeKernel, "_transition", kernel), \
                patch.object(capacity, "_finalize_capacity", wraps=capacity._finalize_capacity) as finalizer, \
                self.assertRaises(semantics.RevocationSemanticsError) as caught:
            self.verify(fixture)
        self.assertEqual((len(kernels), finalizer.call_count), (1, 1))
        self.assertIsInstance(caught.exception.__cause__, capacity.AuditCapacityError)

    def test_independent_full_phase_accounting_and_proof_only_snapshot_are_exact(self):
        for options in ({}, {"separate_signer": True}, {"approval": False, "include_audit": False}):
            fixture = SemanticFixture(**options)
            expected = independent_metrics(fixture)
            with self.subTest(options=options):
                actual = self.verify(fixture)
                self.assert_complete(fixture, actual)
                for phase in PHASES:
                    self.assertEqual(units(getattr(actual.metrics, phase)), expected[phase], phase)
                self.assertEqual((actual.metrics.total_hashes, actual.metrics.total_input_bytes,
                                  actual.metrics.total_json_nodes), expected["total"])
                packaging = actual.proof.packaging
                self.assertEqual((packaging.total_hashes, packaging.total_input_bytes,
                                  packaging.total_json_nodes), expected["proof_snapshot"])
                self.assertEqual(units(packaging.peak_reserved_work), expected["retained_peak"])
                self.assertEqual(units(packaging.reserved_compact_work), (1, 262_144, 2048))
                self.assertEqual(units(packaging.capture), expected["capture"])
                self.assertEqual(actual.metrics.request_binding.hash_work, 2)
                self.assertEqual(actual.metrics.receipt.hash_work, 8)
                self.assertEqual(actual.metrics.kernel.hash_work, 4 + 3 * len(fixture.kernel_fixture.subjects))

    def test_independent_cumulative_admission_peak_and_each_one_less_deny(self):
        fixture = SemanticFixture()
        expected = independent_metrics(fixture)
        quotas = dict(zip(("max_hashes", "max_input_bytes", "max_json_nodes"), expected["admission"]))
        with patch.object(mixed, "_verify", wraps=mixed._verify) as proof:
            actual = self.verify(fixture, limits=accounting.QueryReadValidationLimits(**quotas))
        self.assert_complete(fixture, actual)
        self.assertEqual(proof.call_count, 1)
        for field in quotas:
            lower = {**quotas, field: quotas[field] - 1}
            with self.subTest(field=field), self.assertRaises(semantics.RevocationSemanticsError):
                self.verify(fixture, limits=accounting.QueryReadValidationLimits(**lower))
        # Proof finalization's reserve is not a new semantic allowance. Its
        # actual spent counters survive release before kernel and capacity.
        self.assertEqual((actual.metrics.total_hashes, actual.metrics.total_input_bytes,
                          actual.metrics.total_json_nodes), expected["total"])

    def test_late_semantic_budget_denial_does_not_retry_or_replace_the_proof_ledger(self):
        fixture = SemanticFixture()
        expected = independent_metrics(fixture)
        # Final mutation comparison is node-heavy and hash-free. These genuine
        # full semantic passes exceed the bounded proof-finalization node hold.
        self.assertGreater(expected["total"][2], expected["retained_peak"][2])
        limits = list(expected["admission"])
        limits[2] = expected["total"][2] - 1
        real_equal = semantics._canonical_equal
        phases = []

        def compare(left, right, **kwargs):
            phases.append((kwargs["label"], kwargs["work"].metrics))
            return real_equal(left, right, **kwargs)

        with patch.object(semantics, "_canonical_equal", compare), \
                patch.object(mixed, "_verify", wraps=mixed._verify) as proof, \
                patch.object(capacity, "_finalize_capacity", wraps=capacity._finalize_capacity) as finalizer, \
                self.assertRaises(semantics.RevocationSemanticsError) as caught:
            self.verify(fixture, limits=accounting.QueryReadValidationLimits(*limits))
        self.assertEqual((proof.call_count, finalizer.call_count), (1, 1))
        self.assertEqual(phases[-1][0], "proved mutations differ from genuine kernel and capacity semantics")
        self.assertEqual(phases[-1][1].hash_work, expected["total"][0])
        self.assertIsInstance(caught.exception.__cause__, accounting.QueryReadWorkError)

    def test_observations_remain_detached_non_authoritative_and_public_planning_stays_closed(self):
        fixture = SemanticFixture()
        actual = self.verify(fixture)
        original_bundle = actual.proof.bundle_bytes
        actual.mutations[0]["row"]["caller_changed_returned_observation"] = True
        self.assertNotIn("caller_changed_returned_observation", fixture.final_mutations[0]["row"])
        self.assertEqual(actual.proof.bundle_bytes, original_bundle)
        with self.assertRaises(FrozenInstanceError):
            actual.work_units = 0
        with self.assertRaises(semantics.RevocationSemanticsError):
            self.verify(fixture, bundle=actual.proof)
        # Real import-boundary denial replaces the previously unreachable
        # registry-export/public-call combination; it is not facade evidence.
        request_oracle.assert_registry_import_denial(self)
        # This entrypoint checks supplied before vectors; it neither discovers
        # their provenance/currentness nor initializes the synthetic counter.

    def test_closed_context_shapes_limits_and_lossless_capture_fail_before_hashing(self):
        fixture = SemanticFixture()
        source = accounting.QueryReadValidationLimits()
        invalid = (object(), object.__new__(accounting.QueryReadValidationLimits),
            forged(source, max_hashes=True), forged(source, max_input_bytes=source.max_input_bytes + 1),
            forged(source, max_json_nodes=None))
        for limits in invalid:
            with self.subTest(limits=type(limits)), patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes, \
                    self.assertRaises(semantics.RevocationSemanticsError):
                self.verify(fixture, limits=limits)
            self.assertEqual(hashes.call_count, 0)
        for field, value in (("expected_before", {**fixture.expected_before, "extra": None}),
                             ("bundle", None), ("transition", {"schema": "not-the-proof-transition"}),
                             ("evidence", {**fixture.receipt.evidence, "counter": 1.5})):
            with self.subTest(field=field), patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes, \
                    self.assertRaises(semantics.RevocationSemanticsError):
                self.verify(fixture, **{field: value})
            self.assertEqual(hashes.call_count, 0)

    def test_actual_private_handoff_preserves_already_consumed_work_through_hold_release(self):
        fixture = SemanticFixture()
        expected = independent_metrics(fixture)
        prior = (3, 17, 5)
        quotas = add(expected["admission"], prior)
        ledger = retained._PackagingLedger(accounting.QueryReadValidationLimits(*quotas), comparing=True)
        ledger.work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        supplied = fixture.inputs()
        key = supplied.pop("verifier_public_key")
        owned, capture = semantics._capture(ledger=ledger, **supplied)
        original_work = ledger.work
        actual = semantics._verify(owned, ledger, capture, key)
        self.assert_complete(fixture, actual)
        self.assertIs(ledger.work, original_work)
        self.assertEqual(units(ledger.work.metrics), add(expected["total"], prior))
        self.assertEqual(units(actual.proof.packaging.peak_reserved_work), add(expected["retained_peak"], prior))
        for phase in PHASES:
            self.assertEqual(units(getattr(actual.metrics, phase)), expected[phase])
        self.assertEqual((ledger.work.limits.max_hashes, ledger.work.limits.max_input_bytes,
                          ledger.work.limits.max_json_nodes), quotas)
        # This private worker accepts an already-owned graph, not a success
        # token. Public calls always capture raw inputs and abort on failures.


if __name__ == "__main__":
    unittest.main()
