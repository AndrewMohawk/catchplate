#!/usr/bin/env python3
"""Retained mixed proof roundtrips using genuine source and proof workers.

Literal envelopes, independent population roots and independently counted
phase work define expected bytes. Observers always delegate the real worker.
These synthetic component inputs are not signed assertions, trusted time,
kernel-approved mutations, initialized capacity or independently current roots.
All authored controls are source-only and unrun.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, fields
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_proof_bundle as retained
import authority_revocation_observation_fixture as fixture_oracle
import test_authority_counted_root_transition as root_oracle
import test_authority_query_reads_measured as work_oracle
import test_authority_revocation_read_write as mixed_oracle


BUNDLE_SCHEMA = "serverware.policyAuthorityRevocationProofBundle/v1"
BUNDLE_PROFILE = "serverware.policyAuthorityRevocationProofBundleProfile/v1"
TRANSITION_SCHEMA = "serverware.policyAuthorityRevocationReadWriteTransition/v1"
TRANSITION_PROFILE = "serverware.policyAuthorityRevocationReadWriteTransitionProfile/v1"
SOURCE_REVISION = "serverware.policyCandidateAuthoritySource/2026-07-30.213"
COUNTED_PROFILE = "serverware.policyAuthorityCountedIndex/v1"
PHASES = (("generation", "generation"), ("declarationBinding", "declaration_binding"),
    ("observationValidation", "observation_validation"), ("pointBinding", "point_binding"),
    ("proofWork", "proof_work"), ("completeBinding", "complete_binding"))
PRIMARY_METRICS = {"selected_rows": "selectedRows", "mutations": "mutations",
    "proof_vectors": "proofVectors", "proof_child_slots": "proofChildSlots",
    "recomputed_ancestors": "recomputedAncestors", "hash_work": "hashWork",
    "input_bytes": "inputBytes", "json_nodes": "jsonNodes"}


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def graph_depth(value):
    """Independent maximum JSON value/key depth; each document root is zero."""
    pending = [(value, 0)]
    deepest = 0
    while pending:
        current, depth = pending.pop()
        deepest = max(deepest, depth)
        if type(current) is dict:
            pending.extend((item, depth + 1) for pair in current.items() for item in pair)
        elif type(current) in (list, tuple):
            pending.extend((item, depth + 1) for item in current)
    return deepest


def digest(domain, encoded):
    value = hashlib.sha256(domain.encode("ascii") + b"\0")
    value.update(len(encoded).to_bytes(8, "big"))
    value.update(encoded)
    return "sha256:" + value.hexdigest()


def raw_document(fixture):
    """Independent normalized evidence, not the producer's capture helper."""
    result = copy.deepcopy(fixture.read_write.ownership_document())
    result.update(requestDigest=fixture.request_digest,
        assertionBinding=copy.deepcopy(fixture.assertion_binding),
        queryReads=[{"queryId": record.query_id,
            "declaredQueryJson": record.declared_query_json.decode("ascii"),
            "resolvedQueryJson": record.resolved_query_json.decode("ascii"),
            "addresses": [{"table": address.table, "keyJson": address.key_json.decode("ascii"),
                "keyDigest": address.key_digest, "present": address.present} for address in record.addresses],
            "returnedRowCount": record.returned_row_count} for record in fixture.query_reads])
    return result


def root_document(root):
    return {"table": root.table, "rootRevision": root.root_revision,
            "rootDigest": root.root_digest, "leafCount": root.leaf_count}


def primary_document(fixture):
    composition = fixture.read_write
    reader = composition.read
    value = {"schema": "serverware.policyAuthorityPrimaryRootTransition/v1",
             "profile": "serverware.policyAuthorityPrimaryRootTransitionProfile/v2"}
    for root_class, prefix in (("business", "business"), ("authorization", "authorization")):
        tables = [item.table for item in reader.contracts if item.root_class == root_class]
        value[prefix + "BeforeRoots"] = [root_document(reader.trees[table].root) for table in tables]
        value[prefix + "AfterRoots"] = [root_document(composition.after_trees[table].root) for table in tables]
    value["metrics"] = {PRIMARY_METRICS[name]: count
        for name, count in composition.writer_metrics()["primary"].items()}
    return value


def counted_heads(fixture, *, after=False):
    result = []
    for name, (revision, root) in fixture.read_write.heads.items():
        if after and name in fixture.read_write.indexes:
            changed = fixture.read_write.indexes[name]
            revision += changed["revision_delta"]
            root = changed["after"].root
        result.append({"indexId": name, "indexRevision": revision,
                       "rootDigest": root.digest, "leafCount": root.count})
    return result


def phase_metrics(fixture):
    expected = mixed_oracle.independent_metrics(fixture)
    return {wire_name: {"hashWork": expected[attribute]["hash_work"],
        "inputBytes": expected[attribute]["input_bytes"], "jsonNodes": expected[attribute]["json_nodes"]}
        for wire_name, attribute in PHASES}


def expected_documents(fixture):
    bundle = {"schema": BUNDLE_SCHEMA, "profile": BUNDLE_PROFILE,
              "sourceRevision": SOURCE_REVISION, "inputs": raw_document(fixture)}
    phases = phase_metrics(fixture)
    metrics = {**phases, **{name: sum(value[name] for value in phases.values())
        for name in ("hashWork", "inputBytes", "jsonNodes")}}
    transition = {"schema": TRANSITION_SCHEMA, "profile": TRANSITION_PROFILE,
        "sourceRevision": SOURCE_REVISION, "operation": fixture_oracle.OPERATION,
        "requestDigest": fixture.request_digest, "cutoffUs": fixture.cutoff_us,
        "assertionBinding": copy.deepcopy(fixture.assertion_binding), "countedProfile": COUNTED_PROFILE,
        "projectionManifestDigest": root_oracle.projection_manifest(),
        "proofBundleDigest": digest(BUNDLE_SCHEMA, wire(bundle)),
        "primaryTransition": primary_document(fixture), "indexBeforeHeads": counted_heads(fixture),
        "indexAfterHeads": counted_heads(fixture, after=True), "metrics": metrics}
    return bundle, transition


def units(hashes=0, input_bytes=0, json_nodes=0):
    return {"hash_work": hashes, "input_bytes": input_bytes, "json_nodes": json_nodes}


def add_units(*values):
    return {name: sum(value[name] for value in values)
            for name in ("hash_work", "input_bytes", "json_nodes")}


def observed_units(value):
    return {name: getattr(value, name) for name in ("hash_work", "input_bytes", "json_nodes")}


def forged(value, **changes):
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(value, field.name)))
    return result


def expected_packaging(fixture, *, replay=False):
    """Charge actual pass classes, with separate conservative final hold."""
    bundle, transition = expected_documents(fixture)
    bundle_size, bundle_nodes = len(wire(bundle)), work_oracle.graph_nodes(bundle)
    compact_size, compact_nodes = len(wire(transition)), work_oracle.graph_nodes(transition)
    raw = bundle["inputs"]
    raw_decode = (0 if replay else sum(len(record.declared_query_json) + len(record.resolved_query_json)
        + sum(len(address.key_json) for address in record.addresses) for record in fixture.query_reads))
    captured = {"bundle": bundle, "transition": transition} if replay else raw
    capture = units(0, len(wire(captured)), work_oracle.graph_nodes(captured))
    claim = units(0, 2 * compact_size, 2 * compact_nodes) if replay else units()
    bundle_encoding = units(1, 2 * bundle_size, 2 * bundle_nodes)
    verification = {name: units(value["hashWork"], value["inputBytes"], value["jsonNodes"])
                    for name, value in phase_metrics(fixture).items()}
    final = units(1, (4 if replay else 2) * compact_size, 2 * compact_nodes)
    reserved = units(1, (4 if replay else 2) * 65_536, 2 * 1024)
    spent = add_units(units(0, raw_decode), capture, claim, bundle_encoding, *verification.values())
    return {"raw_decode_bytes": raw_decode, "capture": capture, "claim_encoding": claim,
        "bundle_encoding": bundle_encoding, "verification": verification, "finalization": final,
        "reserved_compact_work": reserved, "peak_reserved_work": add_units(spent, reserved),
        "total": add_units(spent, final)}


def named_record(bundle, fragment):
    records = [item for item in bundle["inputs"]["queryReads"] if f"/{fragment}/" in item["queryId"]]
    if len(records) != 1:
        raise AssertionError("fixture needs one exact source query")
    return records[0]


def rebound_claim(bundle, transition):
    result = copy.deepcopy(transition)
    result["proofBundleDigest"] = digest(BUNDLE_SCHEMA, wire(bundle))
    return result


class RevocationProofBundleTests(unittest.TestCase):
    def derive(self, fixture, **changes):
        inputs = fixture.inputs()
        inputs.update(changes)
        return retained.derive_revocation_proof_bundle(**inputs)

    def assert_documents(self, fixture, result):
        bundle, transition = expected_documents(fixture)
        self.assertEqual(result.bundle_bytes, wire(bundle))
        self.assertEqual(result.transition_bytes, wire(transition))
        self.assertEqual(result.bundle_digest, digest(BUNDLE_SCHEMA, wire(bundle)))
        self.assertEqual(result.transition_digest, digest(TRANSITION_SCHEMA, wire(transition)))
        self.assertEqual(len(bundle), 4)
        self.assertEqual(len(bundle["inputs"]), 15)
        self.assertEqual(len(transition), 14)
        self.assertEqual(len(transition["metrics"]), 9)
        self.assertEqual(len(transition["primaryTransition"]), 7)
        self.assertTrue(all(len(head) == 4 for head in transition["indexBeforeHeads"]))
        return bundle, transition

    def test_exact_raw_bundle_compact_wire_and_digest_match_independent_oracles(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        result = self.derive(fixture)
        bundle, transition = self.assert_documents(fixture, result)
        self.assertEqual(len(bundle["inputs"]["queryReads"]), 12)
        self.assertEqual(len(transition["indexBeforeHeads"]), 8)
        self.assertEqual(transition["primaryTransition"]["metrics"]["mutations"], 3)
        # Encoding/capture are invocation costs, not retained proof semantics.
        self.assertNotIn("ownershipBytes", transition["metrics"])
        self.assertNotIn("rawDecodeBytes", transition["metrics"])
        self.assertNotEqual(result.bundle_digest, result.transition_digest)

    def test_actual_json_roundtrip_recomputes_identical_retained_documents(self):
        fixture = fixture_oracle.RevocationObservationFixture(pending_count=2)
        derived = self.derive(fixture)
        # The public replay boundary accepts decoded JSON, not DTOs or bytes.
        bundle = json.loads(derived.bundle_bytes)
        transition = json.loads(derived.transition_bytes)
        replayed = retained.verify_revocation_proof_bundle(bundle=bundle, transition=transition)
        self.assert_documents(fixture, replayed)
        self.assertEqual((replayed.bundle_bytes, replayed.bundle_digest, replayed.transition_bytes,
                          replayed.transition_digest),
                         (derived.bundle_bytes, derived.bundle_digest, derived.transition_bytes,
                          derived.transition_digest))
        self.assertIsNot(replayed.primary, derived.primary)
        self.assertEqual(replayed.packaging.raw_decode_bytes, 0)
        self.assertGreater(derived.packaging.raw_decode_bytes, 0)
        self.assertNotEqual(replayed.packaging.total_input_bytes, derived.packaging.total_input_bytes)

    def test_source_variants_preserve_empty_roles_read_only_heads_and_counter_boundary(self):
        variants = ({"separate_signer": True}, {"pending_count": 2, "include_audit": False},
                    {"counter_present": False}, {"audit_present": True})
        for options in variants:
            with self.subTest(options=options):
                fixture = fixture_oracle.RevocationObservationFixture(**options)
                result = self.derive(fixture)
                bundle, transition = self.assert_documents(fixture, result)
                self.assertEqual(named_record(bundle, "approvals")["addresses"], [])
                before = {head["indexId"]: head for head in transition["indexBeforeHeads"]}
                after = {head["indexId"]: head for head in transition["indexAfterHeads"]}
                for name in set(before) - set(fixture.read_write.indexes):
                    self.assertEqual(before[name], after[name])
                if options.get("counter_present") is False:
                    self.assertFalse(named_record(bundle, "global_audit_capacity_before_v1")["addresses"][0]["present"])
                if options.get("audit_present"):
                    self.assertTrue(named_record(bundle, "audit_0")["addresses"][0]["present"])

    def test_each_entrypoint_calls_one_real_private_verifier_and_retains_actual_primary(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        bundle, transition = expected_documents(fixture)
        original = retained.mixed._verify
        for replay in (False, True):
            observed = []
            captures = []
            actual_visit = retained.query_batch._JSONCapture.visit

            def genuine(*args, **kwargs):
                result = original(*args, **kwargs)
                observed.append((args, result))
                return result

            def visit(copier, value, depth=0, ancestors=frozenset()):
                # Replay starts its synthetic pair at -1 so each retained wire
                # document begins at zero. Count the actual top invocation,
                # never its two children or measurement-only envelope walks.
                if not ancestors and copier.retain:
                    captures.append(value)
                return actual_visit(copier, value, depth, ancestors)

            with self.subTest(replay=replay), patch.object(retained.mixed, "_verify", side_effect=genuine) as worker, \
                    patch.object(retained.query_batch._JSONCapture, "visit", new=visit), \
                    patch.object(retained.mixed, "verify_revocation_read_write_inputs",
                        wraps=retained.mixed.verify_revocation_read_write_inputs) as public, \
                    patch.object(retained.mixed.read_write, "verify_complete_read_write_batch",
                        wraps=retained.mixed.read_write.verify_complete_read_write_batch) as older_public:
                result = (retained.verify_revocation_proof_bundle(bundle=bundle, transition=transition)
                          if replay else self.derive(fixture))
            self.assertEqual(worker.call_count, 1)
            self.assertEqual((public.call_count, older_public.call_count), (0, 0))
            self.assertEqual(len(captures), 1)
            self.assertIs(result.primary, observed[0][1].write.primary)
            self.assertEqual(observed[0][0][0], bundle["inputs"])

    def test_derive_owns_every_raw_graph_before_first_real_bundle_hash(self):
        fixture = fixture_oracle.RevocationObservationFixture(pending_count=2)
        expected_bundle, expected_transition = expected_documents(fixture)
        inputs = fixture.inputs()
        original = retained.core.framed_digest
        calls = []

        def genuine(domain, *frames):
            if not calls:
                self.assertEqual(domain, BUNDLE_SCHEMA)
                self.assertEqual(frames, (wire(expected_bundle),))
                inputs["arguments"]["record_id"] = "changed-after-capture"
                inputs["assertion_binding"]["challengeId"] = "changed-after-capture"
                for roots in (inputs["business_before_roots"], inputs["authorization_before_roots"]):
                    for root in roots:
                        root["rootRevision"] += 1
                selected = next(item for item in inputs["selected_rows"] if item["present"])
                selected["row"]["after_capture"] = True
                inputs["before_proofs"][-1]["rootRevision"] += 1
                inputs["mutations"][-1]["row"]["after_capture"] = True
                terminal = inputs["query_frontiers"][-2].frontier[0]
                attribute = "primary_row_digest" if hasattr(terminal, "primary_row_digest") else "digest"
                object.__setattr__(terminal, attribute, "sha256:" + "f" * 64)
                object.__setattr__(inputs["query_reads"][-1], "resolved_query_json", b"{}")
            calls.append(domain)
            return original(domain, *frames)

        with patch.object(retained.core, "framed_digest", side_effect=genuine):
            result = retained.derive_revocation_proof_bundle(**inputs)
        self.assertEqual(result.bundle_bytes, wire(expected_bundle))
        self.assertEqual(result.transition_bytes, wire(expected_transition))
        self.assertEqual(calls[0], BUNDLE_SCHEMA)
        self.assertEqual(calls[-1], TRANSITION_SCHEMA)

    def test_replay_owns_both_raw_evidence_and_claim_before_first_real_bundle_hash(self):
        fixture = fixture_oracle.RevocationObservationFixture(pending_count=2)
        bundle, transition = expected_documents(fixture)
        expected_bundle, expected_transition = wire(bundle), wire(transition)
        original = retained.core.framed_digest
        calls = []

        def genuine(domain, *frames):
            if not calls:
                self.assertEqual((domain, frames), (BUNDLE_SCHEMA, (expected_bundle,)))
                raw = bundle["inputs"]
                raw["arguments"]["record_id"] = "changed-after-capture"
                raw["mutations"][-1]["row"]["after_capture"] = True
                raw["beforeProofs"][-1]["rootRevision"] += 1
                raw["queryFrontiers"][-1]["frontier"].clear()
                raw["writeFrontiers"][-1]["frontier"].clear()
                raw["queryReads"][-1]["resolvedQueryJson"] = "{}"
                transition["indexAfterHeads"][0]["indexRevision"] += 1
                transition["metrics"]["proofWork"]["inputBytes"] += 1
            calls.append(domain)
            return original(domain, *frames)

        with patch.object(retained.core, "framed_digest", side_effect=genuine):
            result = retained.verify_revocation_proof_bundle(bundle=bundle, transition=transition)
        self.assertEqual(result.bundle_bytes, expected_bundle)
        self.assertEqual(result.transition_bytes, expected_transition)
        self.assertNotEqual(wire(bundle), expected_bundle)
        self.assertNotEqual(wire(transition), expected_transition)

    def test_retained_bytes_are_immutable_observations_not_success_inputs(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        result = self.derive(fixture)
        for name in ("bundle_bytes", "transition_bytes"):
            self.assertIs(type(getattr(result, name)), bytes)
            with self.assertRaises(FrozenInstanceError):
                setattr(result, name, b"{}")
        decoded = json.loads(result.bundle_bytes)
        decoded["inputs"]["arguments"]["record_id"] = "detached"
        self.assertEqual(json.loads(result.bundle_bytes)["inputs"]["arguments"]["record_id"],
                         fixture_oracle.TARGET_ID)
        bundle, transition = expected_documents(fixture)
        for bad_bundle, bad_transition in ((result, transition), (bundle, result),
                                            (result.bundle_bytes, transition),
                                            (bundle, result.transition_bytes)):
            with self.subTest(kind=(type(bad_bundle), type(bad_transition))), \
                    patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained.verify_revocation_proof_bundle(bundle=bad_bundle, transition=bad_transition)
            self.assertEqual(actual.call_count, 0)
        # Even the actual primary result cannot replace the original proof graph.
        with self.assertRaises(retained.RevocationProofBundleError):
            self.derive(fixture, selected_rows=result.primary)

    def test_closed_envelopes_profiles_and_source_revision_deny_before_proof(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        bundle, transition = expected_documents(fixture)
        cases = []
        for field in ("schema", "profile", "sourceRevision"):
            changed = copy.deepcopy(bundle)
            changed[field] += "-other"
            cases.append((changed, transition))
        for field in ("schema", "profile", "sourceRevision", "countedProfile"):
            changed = copy.deepcopy(transition)
            changed[field] += "-other"
            cases.append((bundle, changed))
        extra = copy.deepcopy(bundle)
        extra["successfulResult"] = {}
        cases.append((extra, transition))
        missing = copy.deepcopy(bundle)
        del missing["inputs"]["queryReads"]
        cases.append((missing, transition))
        extra = copy.deepcopy(transition)
        extra["scope"] = "current-root-authority"
        cases.append((bundle, extra))
        for ordinal, (bad_bundle, bad_transition) in enumerate(cases):
            with self.subTest(case=ordinal), \
                    patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual, \
                    patch.object(retained.core, "framed_digest", wraps=retained.core.framed_digest) as hashes:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained.verify_revocation_proof_bundle(bundle=bad_bundle, transition=bad_transition)
            self.assertEqual((actual.call_count, hashes.call_count), (0, 0))

    def test_compact_primary_and_counted_inventory_changes_do_not_pass_replay(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        bundle, transition = expected_documents(fixture)
        claims = []
        missing_primary = copy.deepcopy(transition)
        missing_primary["primaryTransition"]["businessAfterRoots"].pop()
        claims.append(missing_primary)
        read_only = next(name for name in fixture.read_write.heads if name not in fixture.read_write.indexes)
        missing_head = copy.deepcopy(transition)
        missing_head["indexAfterHeads"] = [head for head in missing_head["indexAfterHeads"]
            if head["indexId"] != read_only]
        claims.append(missing_head)
        revision = copy.deepcopy(transition)
        next(head for head in revision["indexAfterHeads"] if head["indexId"] == read_only)["indexRevision"] += 1
        claims.append(revision)
        swapped = copy.deepcopy(transition)
        swapped["indexBeforeHeads"][0], swapped["indexBeforeHeads"][1] = \
            swapped["indexBeforeHeads"][1], swapped["indexBeforeHeads"][0]
        claims.append(swapped)
        alias = copy.deepcopy(transition)
        alias["indexBeforeHeads"][0]["indexRevision"] = True
        claims.append(alias)
        for ordinal, claim in enumerate(claims):
            with self.subTest(case=ordinal):
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained.verify_revocation_proof_bundle(bundle=bundle, transition=claim)
        # A legal integer change of a retained read-only revision is not just
        # a malformed-token test: it must differ from genuine recomputation.
        with patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual:
            with self.assertRaises(retained.RevocationProofBundleError):
                retained.verify_revocation_proof_bundle(bundle=bundle, transition=revision)
        self.assertEqual(actual.call_count, 1)

    def test_compact_context_and_manifest_claims_are_compared_to_real_results(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        bundle, transition = expected_documents(fixture)
        changes = ({"requestDigest": "sha256:" + "8" * 64},
                   {"cutoffUs": fixture.cutoff_us + 1},
                   {"assertionBinding": {**fixture.assertion_binding, "challengeId": "other-challenge"}},
                   {"projectionManifestDigest": "sha256:" + "9" * 64},
                   {"proofBundleDigest": "sha256:" + "a" * 64})
        for change in changes:
            with self.subTest(fields=tuple(change)), \
                    patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained.verify_revocation_proof_bundle(bundle=bundle,
                        transition={**transition, **change})
            self.assertEqual(actual.call_count, 1)

    def test_consistently_forged_phase_totals_still_require_genuine_recomputation(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        bundle, transition = expected_documents(fixture)
        for phase, _ in PHASES:
            forged = copy.deepcopy(transition)
            forged["metrics"][phase]["inputBytes"] += 1
            forged["metrics"]["inputBytes"] += 1
            with self.subTest(phase=phase), \
                    patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained.verify_revocation_proof_bundle(bundle=bundle, transition=forged)
            self.assertEqual(actual.call_count, 1)
        forged = copy.deepcopy(transition)
        forged["primaryTransition"]["metrics"]["inputBytes"] += 1
        with self.assertRaises(retained.RevocationProofBundleError):
            retained.verify_revocation_proof_bundle(bundle=bundle, transition=forged)

    def test_rehashed_bundle_cannot_hide_false_primary_rows_or_proof_siblings(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        bundle, transition = expected_documents(fixture)
        wrong_row = copy.deepcopy(bundle)
        present = next(item for item in wrong_row["inputs"]["selectedRows"] if item["present"])
        present["row"]["uncommitted_field"] = "not in the independently committed full row"
        wrong_proof = copy.deepcopy(bundle)
        proof = wrong_proof["inputs"]["beforeProofs"][0]
        vector = proof["siblings"][0]
        slot = (int(vector["selectedNibble"], 16) + 1) % 16
        vector["childDigests"][slot] = "sha256:" + "f" * 64
        fixture_oracle.composition_oracle.primary_oracle.refresh_proof_digest(proof)
        for bad in (wrong_row, wrong_proof):
            with self.subTest(kind="row" if bad is wrong_row else "proof"), \
                    patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained.verify_revocation_proof_bundle(bundle=bad,
                        transition=rebound_claim(bad, transition))
            self.assertEqual(actual.call_count, 1)

    def test_rehashed_bundle_frontier_omissions_fail_real_query_and_write_engines(self):
        fixture = fixture_oracle.RevocationObservationFixture(pending_count=2)
        bundle, transition = expected_documents(fixture)
        for family in ("queryFrontiers", "writeFrontiers"):
            bad = copy.deepcopy(bundle)
            frontier = next(item["frontier"] for item in bad["inputs"][family]
                            if any(terminal["kind"] == "leaf" for terminal in item["frontier"]))
            position = next(index for index, item in enumerate(frontier) if item["kind"] == "leaf")
            del frontier[position]
            with self.subTest(family=family), \
                    patch.object(retained.mixed.read_write, "_verify",
                        wraps=retained.mixed.read_write._verify) as proof_worker:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained.verify_revocation_proof_bundle(bundle=bad,
                        transition=rebound_claim(bad, transition))
            self.assertEqual(proof_worker.call_count, 1)

    def test_rehashed_records_preserve_exact_point_binding_and_genuine_complete_order(self):
        fixture = fixture_oracle.RevocationObservationFixture(separate_signer=True, pending_count=2)
        bundle, transition = expected_documents(fixture)
        swapped = copy.deepcopy(bundle)
        target = named_record(swapped, "revoked_credential")
        signer = named_record(swapped, "assertion_credential")
        target["addresses"], signer["addresses"] = signer["addresses"], target["addresses"]
        reversed_members = copy.deepcopy(bundle)
        pending = named_record(reversed_members, "sessions_pending_webauthn")
        self.assertEqual(len(pending["addresses"]), 2)
        pending["addresses"].reverse()
        for bad, expected_proof_calls in ((swapped, 0), (reversed_members, 1)):
            with self.subTest(proof_calls=expected_proof_calls), \
                    patch.object(retained.mixed.read_write, "_verify",
                        wraps=retained.mixed.read_write._verify) as proof_worker:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained.verify_revocation_proof_bundle(bundle=bad,
                        transition=rebound_claim(bad, transition))
            self.assertEqual(proof_worker.call_count, expected_proof_calls)

    def test_full_recipe_empty_roles_and_context_are_not_caller_selectable(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        bundle, transition = expected_documents(fixture)
        missing = copy.deepcopy(bundle)
        empty = named_record(missing, "approvals")
        self.assertEqual(empty["returnedRowCount"], 0)
        missing["inputs"]["queryReads"].remove(empty)
        permuted = copy.deepcopy(bundle)
        permuted["inputs"]["queries"][0], permuted["inputs"]["queries"][1] = \
            permuted["inputs"]["queries"][1], permuted["inputs"]["queries"][0]
        extra = copy.deepcopy(bundle)
        record = copy.deepcopy(extra["inputs"]["queryReads"][0])
        record["queryId"] = "serverware.policyAuthorityQuery/unknown-extra/v1"
        extra["inputs"]["queryReads"].append(record)
        wrong_context = copy.deepcopy(bundle)
        wrong_context["inputs"]["assertionBinding"]["challengeId"] = "other-challenge"
        for ordinal, bad in enumerate((missing, permuted, extra, wrong_context)):
            with self.subTest(case=ordinal):
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained.verify_revocation_proof_bundle(bundle=bad,
                        transition=rebound_claim(bad, transition))
        # With J=0 the source recipe does not use the request digest for audit
        # IDs, but the compact context still binds its exact retained value.
        no_audit = fixture_oracle.RevocationObservationFixture(include_audit=False)
        raw, claim = expected_documents(no_audit)
        raw["inputs"]["requestDigest"] = "sha256:" + "8" * 64
        with self.assertRaises(retained.RevocationProofBundleError):
            retained.verify_revocation_proof_bundle(bundle=raw, transition=rebound_claim(raw, claim))

    def test_no_caller_query_json_is_parsed_and_keyword_inventory_is_closed(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        bundle, transition = expected_documents(fixture)
        for replay in (False, True):
            with self.subTest(replay=replay), patch.object(json, "loads", wraps=json.loads) as loads:
                if replay:
                    retained.verify_revocation_proof_bundle(bundle=bundle, transition=transition)
                else:
                    self.derive(fixture)
            # Only the source worker's own canonical business-intent value is
            # parsed; declared/resolved query strings are never executable JSON.
            self.assertEqual(loads.call_count, 1)
            self.assertEqual(loads.call_args.args[0], wire(fixture.values).decode("ascii"))
        extra = fixture.inputs()
        extra["successful_result"] = {}
        replaced = fixture.inputs()
        replaced["successful_result"] = replaced.pop("before_proofs")
        for inputs in (extra, replaced):
            with patch.object(retained.mixed, "_capture", wraps=retained.mixed._capture) as capture, \
                    patch.object(retained.core, "framed_digest", wraps=retained.core.framed_digest) as hashes:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained.derive_revocation_proof_bundle(**inputs)
            self.assertEqual((capture.call_count, hashes.call_count), (0, 0))

    def test_all_packaging_units_match_independent_derive_and_replay_pass_oracles(self):
        fixture = fixture_oracle.RevocationObservationFixture(separate_signer=True, pending_count=2)
        bundle, transition = expected_documents(fixture)
        for replay in (False, True):
            expected = expected_packaging(fixture, replay=replay)
            result = (retained.verify_revocation_proof_bundle(bundle=bundle, transition=transition)
                      if replay else self.derive(fixture))
            actual = result.packaging
            with self.subTest(replay=replay):
                self.assertEqual(actual.raw_decode_bytes, expected["raw_decode_bytes"])
                for name in ("capture", "claim_encoding", "bundle_encoding", "finalization",
                             "reserved_compact_work", "peak_reserved_work"):
                    self.assertEqual(observed_units(getattr(actual, name)), expected[name], name)
                self.assertEqual(tuple(name for name, _ in actual.verification), tuple(name for name, _ in PHASES))
                self.assertEqual({name: observed_units(value) for name, value in actual.verification},
                                 expected["verification"])
                self.assertEqual(units(actual.total_hashes, actual.total_input_bytes, actual.total_json_nodes),
                                 expected["total"])
                self.assertGreater(actual.peak_reserved_work.input_bytes, actual.total_input_bytes)
                self.assertGreater(actual.peak_reserved_work.json_nodes, actual.total_json_nodes)
                self.assertEqual(actual.peak_reserved_work.hash_work, actual.total_hashes)
                self.assert_documents(fixture, result)
        # Standalone invocation costs differ, but the retained phase-only
        # metrics and every committed byte survive real derive/replay unchanged.
        self.assertEqual(transition["metrics"]["inputBytes"],
            sum(value["input_bytes"] for value in expected["verification"].values()))

    def test_independent_peak_limits_admit_and_one_less_denies_before_hold_release(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        bundle, transition = expected_documents(fixture)
        original_release = retained._PackagingLedger.release_compact_hold
        for replay in (False, True):
            peak = expected_packaging(fixture, replay=replay)["peak_reserved_work"]
            limits = accounting.QueryReadValidationLimits(peak["hash_work"], peak["input_bytes"], peak["json_nodes"])

            def run(budget):
                return (retained.verify_revocation_proof_bundle(bundle=bundle, transition=transition, limits=budget)
                        if replay else self.derive(fixture, limits=budget))

            with self.subTest(replay=replay, boundary="exact"):
                result = run(limits)
                self.assert_documents(fixture, result)
                self.assertEqual(observed_units(result.packaging.peak_reserved_work), peak)
            for field in ("max_hashes", "max_input_bytes", "max_json_nodes"):
                lowered = {item.name: getattr(limits, item.name) for item in fields(limits)}
                lowered[field] -= 1
                releases = []

                def release(ledger):
                    releases.append(ledger)
                    return original_release(ledger)

                with self.subTest(replay=replay, field=field), \
                        patch.object(retained._PackagingLedger, "release_compact_hold", new=release):
                    with self.assertRaises(retained.RevocationProofBundleError):
                        run(accounting.QueryReadValidationLimits(**lowered))
                self.assertEqual(releases, [])
        # No lowered production constants, fabricated verifier result, or claim
        # that the smaller final actual totals are sufficient admission limits.

    def test_one_ledger_reserves_finalization_before_genuine_verification_and_releases_once(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        bundle, transition = expected_documents(fixture)
        original_verify = retained.mixed._verify
        original_release = retained._PackagingLedger.release_compact_hold
        for replay in (False, True):
            expected = expected_packaging(fixture, replay=replay)
            before_proof = add_units(units(0, expected["raw_decode_bytes"]), expected["capture"],
                                    expected["claim_encoding"], expected["bundle_encoding"])
            observed = []
            released = []

            def genuine(owned, ledger, raw_decode, capture):
                self.assertEqual(observed_units(ledger.work.metrics), before_proof)
                self.assertEqual(observed_units(ledger.reserved), expected["reserved_compact_work"])
                self.assertEqual(ledger.remaining(), (
                    8_000_000 - expected["reserved_compact_work"]["hash_work"] - before_proof["hash_work"],
                    64 * 1024 * 1024 - expected["reserved_compact_work"]["input_bytes"] - before_proof["input_bytes"],
                    1_000_000 - expected["reserved_compact_work"]["json_nodes"] - before_proof["json_nodes"]))
                observed.append(ledger)
                return original_verify(owned, ledger, raw_decode, capture)

            def release(ledger):
                self.assertIs(ledger, observed[0])
                self.assertEqual(observed_units(ledger.work.metrics),
                    add_units(before_proof, *expected["verification"].values()))
                result = original_release(ledger)
                self.assertEqual(ledger.work.limits, accounting.QueryReadValidationLimits())
                released.append(ledger)
                return result

            with self.subTest(replay=replay), patch.object(retained.mixed, "_verify", side_effect=genuine), \
                    patch.object(retained._PackagingLedger, "release_compact_hold", new=release):
                result = (retained.verify_revocation_proof_bundle(bundle=bundle, transition=transition)
                          if replay else self.derive(fixture))
            self.assertEqual((len(observed), len(released)), (1, 1))
            self.assertIs(observed[0], released[0])
            self.assertEqual(observed_units(observed[0].work.metrics), expected["total"])
            with self.assertRaises(retained.RevocationProofBundleError):
                original_release(observed[0])
            self.assertEqual(result.packaging.total_hashes, expected["total"]["hash_work"])

    def test_exact_limits_lossless_shapes_and_wire_caps_deny_before_expensive_steps(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        bundle, transition = expected_documents(fixture)
        source = accounting.QueryReadValidationLimits()

        class LimitSubclass(accounting.QueryReadValidationLimits):
            pass

        invalid = ({}, LimitSubclass(), object.__new__(accounting.QueryReadValidationLimits),
                   forged(source, max_json_nodes=None), forged(source, max_hashes=True),
                   forged(source, max_hashes=8_000_001), forged(source, max_input_bytes=64 * 1024 * 1024 + 1),
                   forged(source, max_json_nodes=1_000_001))
        for limits in invalid:
            with self.subTest(limits_type=type(limits)), \
                    patch.object(retained.core, "framed_digest", wraps=retained.core.framed_digest) as hashes:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained.verify_revocation_proof_bundle(bundle=bundle, transition=transition, limits=limits)
            self.assertEqual(hashes.call_count, 0)
        for replay, byte_hold in ((False, 131_072), (True, 262_144)):
            for limits in (accounting.QueryReadValidationLimits(max_hashes=1),
                           accounting.QueryReadValidationLimits(max_input_bytes=byte_hold),
                           accounting.QueryReadValidationLimits(max_json_nodes=2048)):
                with self.subTest(replay=replay), \
                        patch.object(retained.query_batch._JSONCapture, "visit",
                            wraps=retained.query_batch._JSONCapture.visit) as capture:
                    with self.assertRaises(retained.RevocationProofBundleError):
                        if replay:
                            retained.verify_revocation_proof_bundle(bundle=bundle, transition=transition, limits=limits)
                        else:
                            self.derive(fixture, limits=limits)
                self.assertEqual(capture.call_count, 0)
        for value in (0.5, "\ud800", "nul\0value", object()):
            bad = copy.deepcopy(bundle)
            bad["inputs"]["arguments"]["reason"] = value
            with self.subTest(kind=type(value)), \
                    patch.object(retained.core, "framed_digest", wraps=retained.core.framed_digest) as hashes:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained.verify_revocation_proof_bundle(bundle=bad, transition=transition)
            self.assertEqual(hashes.call_count, 0)
        unknown_terminal = copy.deepcopy(bundle)
        unknown_terminal["inputs"]["queryFrontiers"][0]["frontier"][0]["kind"] = "caller-selected-kind"
        extra_sibling = copy.deepcopy(bundle)
        extra_sibling["inputs"]["beforeProofs"][0]["siblings"][0]["unadmitted"] = True
        too_many_reads = copy.deepcopy(bundle)
        too_many_reads["inputs"]["queryReads"] = [too_many_reads["inputs"]["queryReads"][0]] * 46
        too_many_addresses = copy.deepcopy(bundle)
        first = too_many_addresses["inputs"]["queryReads"][0]
        first["addresses"] = first["addresses"] * 193
        self.assertGreater(sum(len(record["addresses"]) for record in too_many_addresses["inputs"]["queryReads"]), 193)
        self.assertTrue(all(len(record["addresses"]) <= 193 for record in too_many_addresses["inputs"]["queryReads"]))
        for bad in (unknown_terminal, extra_sibling, too_many_reads, too_many_addresses):
            with patch.object(retained.core, "framed_digest", wraps=retained.core.framed_digest) as hashes, \
                    patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained.verify_revocation_proof_bundle(bundle=bad, transition=transition)
            self.assertEqual((hashes.call_count, actual.call_count), (0, 0))
        non_ascii = copy.deepcopy(bundle)
        non_ascii["inputs"]["queryReads"][0]["resolvedQueryJson"] = "{}é"
        # Outer canonical JSON may represent Unicode, but retained query bytes
        # are strict ASCII. That distinction is enforced by real restoration,
        # after bundle hashing and source generation, before proof evaluation.
        with patch.object(retained.core, "framed_digest", wraps=retained.core.framed_digest) as hashes, \
                patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual, \
                patch.object(retained.mixed.read_write, "_verify",
                    wraps=retained.mixed.read_write._verify) as proof_worker:
            with self.assertRaises(retained.RevocationProofBundleError):
                retained.verify_revocation_proof_bundle(bundle=non_ascii, transition=transition)
        self.assertEqual(hashes.call_args_list[0].args[0], BUNDLE_SCHEMA)
        self.assertEqual((actual.call_count, proof_worker.call_count), (1, 0))
        # Direct accounting-component controls at the REAL source output caps;
        # these graphs are intentionally not claimed to be valid transitions.
        for oversized in ({"value": "x" * 65_536}, {"values": [None] * 1024}):
            ledger = retained._PackagingLedger(source, comparing=False)
            with patch.object(retained.core, "canonical_bytes", wraps=retained.core.canonical_bytes) as encoder:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained._bounded_wire(oversized, ledger, maximum_bytes=65_536, maximum_nodes=1024)
            self.assertEqual(encoder.call_count, 0)
            self.assertGreater(ledger.work.input_bytes, 0)
            self.assertGreater(ledger.work.json_nodes, 0)

    def test_real_depth_128_bundle_roundtrips_and_depth_129_denies_without_larger_caps(self):
        def deep_fixture(list_count):
            fixture = fixture_oracle.RevocationObservationFixture()
            nested = 7
            for _ in range(list_count):
                nested = [nested]
            fixture.values["audit_event"] = {"credential_record_id": fixture_oracle.TARGET_ID,
                                               "nested": nested}
            # Rebuild the literal full businessIntent, not merely the outer
            # argument. The actual source worker must still validate/normalize
            # both. Existing audit IDs depend on request/subject, not this body;
            # selected populations and the three synthetic writes are unchanged.
            fixture.arguments = fixture_oracle.recipe_oracle.arguments(fixture.values)
            fixture.read_write.read.intent = copy.deepcopy(fixture.arguments)
            return fixture

        fixture = deep_fixture(122)
        bundle, transition = expected_documents(fixture)
        self.assertEqual(graph_depth(bundle["inputs"]), 127)
        self.assertEqual(graph_depth(bundle), 128)
        self.assertEqual(graph_depth({"bundle": bundle, "transition": transition}), 129)
        with patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual:
            derived = self.derive(fixture)
        self.assertEqual(actual.call_count, 1)
        self.assert_documents(fixture, derived)
        # Real encode/decode loses all private object identity before replay.
        decoded_bundle = json.loads(derived.bundle_bytes)
        decoded_transition = json.loads(derived.transition_bytes)
        with patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual:
            replayed = retained.verify_revocation_proof_bundle(bundle=decoded_bundle,
                                                               transition=decoded_transition)
        self.assertEqual(actual.call_count, 1)
        self.assertEqual((replayed.bundle_bytes, replayed.transition_bytes,
                          replayed.bundle_digest, replayed.transition_digest),
                         (derived.bundle_bytes, derived.transition_bytes,
                          derived.bundle_digest, derived.transition_digest))
        # Changing the initial depth changes no byte/node charges. Preserve the
        # full independently computed pass accounting at this exact boundary.
        for replay, result in ((False, derived), (True, replayed)):
            expected = expected_packaging(fixture, replay=replay)
            self.assertEqual(units(result.packaging.total_hashes, result.packaging.total_input_bytes,
                                   result.packaging.total_json_nodes), expected["total"])

        too_deep = deep_fixture(123)
        oversized = {"schema": BUNDLE_SCHEMA, "profile": BUNDLE_PROFILE,
                     "sourceRevision": SOURCE_REVISION, "inputs": raw_document(too_deep)}
        self.assertEqual(graph_depth(oversized["inputs"]), 128)
        self.assertEqual(graph_depth(oversized), 129)
        for replay in (False, True):
            with self.subTest(replay=replay), \
                    patch.object(retained.core, "framed_digest", wraps=retained.core.framed_digest) as hashes, \
                    patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual:
                with self.assertRaises(retained.RevocationProofBundleError):
                    if replay:
                        retained.verify_revocation_proof_bundle(bundle=oversized, transition=transition)
                    else:
                        self.derive(too_deep)
            self.assertEqual((hashes.call_count, actual.call_count), (0, 0))

    def test_shared_derivation_keeps_actual_graphs_and_genuine_proof_on_exact_existing_work(self):
        fixture = fixture_oracle.RevocationObservationFixture(separate_signer=True)
        inputs = fixture.inputs()
        expected = expected_packaging(fixture)
        expected_bundle, expected_transition = expected_documents(fixture)
        prior = units(7, 101, 13)
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        work.charge(hashes=prior["hash_work"], input_bytes=prior["input_bytes"], json_nodes=prior["json_nodes"])
        entering = work.limits
        actual_verify = retained.mixed._verify
        actual_initialize = accounting._ValidationWork.__init__
        seen, children = [], []
        spent_before_verification = add_units(prior, units(0, expected["raw_decode_bytes"]),
            expected["capture"], expected["bundle_encoding"])
        child_limits = tuple(maximum - expected["reserved_compact_work"][name]
            - spent_before_verification[name] for maximum, name in zip(
                (entering.max_hashes, entering.max_input_bytes, entering.max_json_nodes),
                ("hash_work", "input_bytes", "json_nodes")))

        def initialize(instance, limits):
            # The genuine mixed worker uses one remaining-clamped child for
            # recipe/observation phases, then debits the existing outer work.
            # Observe that real constructor; forbid an unclamped new allowance.
            self.assertEqual((limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes), child_limits)
            self.assertIsNot(instance, work)
            actual_initialize(instance, limits)
            children.append(instance)

        def verify(owned, ledger, raw_decode, capture):
            self.assertIs(ledger.work, work)
            result = actual_verify(owned, ledger, raw_decode, capture)
            seen.append((owned, result))
            return result

        with patch.object(accounting._ValidationWork, "__init__", new=initialize), \
                patch.object(retained.mixed, "_verify", side_effect=verify) as actual, \
                patch.object(retained, "_compact_document", wraps=retained._compact_document) as compact, \
                patch.object(json, "loads", wraps=json.loads) as loads:
            derived = retained._derive_on_work(work=work, **inputs)
        self.assertEqual((actual.call_count, compact.call_count, loads.call_count), (1, 1, 1))
        self.assertEqual(len(children), 1)
        self.assertEqual(observed_units(children[0].metrics), add_units(*(expected["verification"][name]
            for name in ("generation", "declarationBinding", "observationValidation", "pointBinding"))))
        self.assertEqual(loads.call_args.args[0], wire(fixture.values).decode("ascii"))
        self.assertIs(derived.bundle["inputs"], seen[0][0])
        self.assertIs(derived.result, seen[0][1])
        self.assertIs(derived.retained.primary, derived.result.write.primary)
        self.assertEqual((derived.bundle, derived.transition), (expected_bundle, expected_transition))
        self.assertEqual((wire(derived.bundle), wire(derived.transition)),
            (derived.retained.bundle_bytes, derived.retained.transition_bytes))
        self.assert_documents(fixture, derived.retained)
        self.assertEqual(observed_units(work.metrics), add_units(prior, expected["total"]))
        self.assertEqual(observed_units(derived.retained.packaging.peak_reserved_work),
                         add_units(prior, expected["peak_reserved_work"]))
        for name in ("capture", "claim_encoding", "bundle_encoding", "finalization", "reserved_compact_work"):
            self.assertEqual(observed_units(getattr(derived.retained.packaging, name)), expected[name])
        self.assertIs(work.limits, entering)
        self.assertFalse(hasattr(work, "_revocation_packaging_owner"))
        with self.assertRaises(FrozenInstanceError):
            derived.bundle = {}
        # Frozen carrier fields do not turn its ordinary mutable graphs into
        # authority. Immutable bytes retain the original commitment.
        derived.bundle["inputs"]["arguments"]["reason"] = "local-output-mutation"
        self.assertEqual(derived.retained.bundle_bytes, wire(expected_bundle))

    def test_shared_independent_peak_exact_and_one_less_restore_existing_outer_ceiling(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        inputs, expected, prior = fixture.inputs(), expected_packaging(fixture), units(11, 127, 17)
        maximum = add_units(prior, expected["peak_reserved_work"])
        names = ("hash_work", "input_bytes", "json_nodes")
        for dimension in (None, *names):
            bounded = dict(maximum)
            if dimension is not None:
                bounded[dimension] -= 1
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*(bounded[name] for name in names)))
            work.charge(hashes=prior["hash_work"], input_bytes=prior["input_bytes"], json_nodes=prior["json_nodes"])
            entering = work.limits  # May already be a downward outer reservation.
            with self.subTest(dimension=dimension):
                if dimension is None:
                    derived = retained._derive_on_work(work=work, **inputs)
                    self.assert_documents(fixture, derived.retained)
                    self.assertEqual(observed_units(work.metrics), add_units(prior, expected["total"]))
                else:
                    with self.assertRaises(retained.RevocationProofBundleError):
                        retained._derive_on_work(work=work, **inputs)
                    self.assertTrue(all(prior[name] <= getattr(work, name) <= bounded[name] for name in names))
                self.assertIs(work.limits, entering)
                self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_two_real_shared_derivations_accumulate_without_reset_or_proof_shortcut(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        expected, inputs = expected_packaging(fixture), fixture.inputs()
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        entering = work.limits
        observations = []
        with patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual:
            for count in (1, 2):
                derived = retained._derive_on_work(work=work, **inputs)
                observations.append(derived)
                self.assertEqual(observed_units(work.metrics),
                    {name: count * value for name, value in expected["total"].items()})
                self.assertEqual(observed_units(derived.retained.packaging.peak_reserved_work),
                    add_units({name: (count - 1) * value for name, value in expected["total"].items()},
                              expected["peak_reserved_work"]))
                self.assertIs(work.limits, entering)
        self.assertEqual(actual.call_count, 2)
        self.assertIsNot(observations[0].result, observations[1].result)
        self.assertEqual(observations[0].retained.bundle_bytes, observations[1].retained.bundle_bytes)
        self.assertEqual(observations[0].retained.transition_bytes, observations[1].retained.transition_bytes)

    def test_shared_hold_admission_and_closed_work_fail_before_capture_without_refund(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        inputs = fixture.inputs()
        reserve = units(1, 131_072, 2048)
        for dimension, limit_name in (("hash_work", "max_hashes"), ("input_bytes", "max_input_bytes"),
                                      ("json_nodes", "max_json_nodes")):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(**{limit_name: reserve[dimension] + 9}))
            work.charge(**{"hashes" if dimension == "hash_work" else dimension: 10})
            entering, spent = work.limits, work.metrics
            with self.subTest(dimension=dimension), \
                    patch.object(retained.mixed, "_capture", wraps=retained.mixed._capture) as capture:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained._derive_on_work(work=work, **inputs)
            self.assertEqual(capture.call_count, 0)
            self.assertIs(work.limits, entering)
            self.assertEqual(work.metrics, spent)
            self.assertFalse(hasattr(work, "_revocation_packaging_owner"))
        class DerivedWork(accounting._ValidationWork):
            pass
        for bad in (None, {}, DerivedWork(accounting.QueryReadValidationLimits()),
                    object.__new__(accounting._ValidationWork)):
            with self.subTest(type=type(bad).__name__), \
                    patch.object(retained.mixed, "_capture", wraps=retained.mixed._capture) as capture:
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained._derive_on_work(work=bad, **inputs)
            self.assertEqual(capture.call_count, 0)
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        for bad in ({**inputs, "successful_result": {}}, {name: value for name, value in inputs.items() if name != "before_proofs"}):
            with self.assertRaises(retained.RevocationProofBundleError):
                retained._derive_on_work(work=work, **bad)
            self.assertEqual(observed_units(work.metrics), units())

    def test_shared_invalid_genuine_proof_and_driver_style_failure_restore_hold_but_keep_work(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        for driver in (False, True):
            inputs = fixture.inputs()
            if not driver:
                inputs["before_proofs"][0]["rowDigest"] = "sha256:" + "0" * 64
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            work.charge(hashes=3, input_bytes=19, json_nodes=7)
            entering = work.limits
            genuine = retained.mixed._verify
            calls = []
            def verify(*args):
                calls.append(args[1])
                if driver:
                    raise RuntimeError("observer failed after real bundle hash")
                return genuine(*args)
            with self.subTest(driver=driver), patch.object(retained.mixed, "_verify", side_effect=verify):
                with self.assertRaises(RuntimeError if driver else retained.RevocationProofBundleError):
                    retained._derive_on_work(work=work, **inputs)
            self.assertEqual(len(calls), 1)
            self.assertGreaterEqual(work.hash_work, 4)
            self.assertGreater(work.input_bytes, 19)
            self.assertGreater(work.json_nodes, 7)
            self.assertIs(work.limits, entering)
            self.assertFalse(calls[0]._held)
            self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_caught_nested_shared_attachment_cannot_publish_before_or_after_hold_release(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        inputs = fixture.inputs()
        for late in (False, True):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            entering, caught = work.limits, []
            original = retained._bounded_wire
            def encode(value, ledger, **kwargs):
                target = TRANSITION_SCHEMA if late else BUNDLE_SCHEMA
                if value.get("schema") == target and not caught:
                    try:
                        retained._derive_on_work(work=work, **inputs)
                    except retained.RevocationProofBundleError:
                        caught.append(True)
                    else:
                        self.fail("nested shared attachment returned a result")
                return original(value, ledger, **kwargs)
            with self.subTest(late=late), patch.object(retained, "_bounded_wire", side_effect=encode):
                with self.assertRaises(retained.RevocationProofBundleError):
                    retained._derive_on_work(work=work, **inputs)
            self.assertEqual(caught, [True])
            self.assertGreater(work.input_bytes, 0)
            self.assertIs(work.limits, entering)
            self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_shared_source_graphs_are_owned_before_hash_and_original_two_tuple_seam_remains(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        inputs = fixture.inputs()
        expected_bundle, expected_transition = expected_documents(fixture)
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        original = retained.core.framed_digest
        changed = []
        def digest_and_change(domain, *frames):
            if domain == BUNDLE_SCHEMA and not changed:
                changed.append(True)
                inputs["arguments"]["reason"] = "changed-after-capture"
                inputs["selected_rows"][0]["keyDigest"] = "sha256:" + "0" * 64
                inputs["before_proofs"][0]["rowDigest"] = "sha256:" + "1" * 64
            return original(domain, *frames)
        with patch.object(retained.core, "framed_digest", side_effect=digest_and_change):
            derived = retained._derive_on_work(work=work, **inputs)
        self.assertEqual(changed, [True])
        self.assertEqual((derived.bundle, derived.transition), (expected_bundle, expected_transition))
        original_compute = retained._compute_and_package
        tuples = []
        def compute(**kwargs):
            result = original_compute(**kwargs)
            tuples.append(result)
            return result
        with patch.object(retained, "_compute_and_package", side_effect=compute), \
                patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual:
            public = self.derive(fixture)
        self.assertEqual(actual.call_count, 1)
        self.assertEqual(len(tuples), 1)
        self.assertIs(type(tuples[0]), tuple)
        self.assertEqual(len(tuples[0]), 2)
        self.assertIs(public, tuples[0][0])

    def test_shared_original_limit_corruption_denies_before_release_and_after_final_hash(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        expected, inputs, prior = expected_packaging(fixture), fixture.inputs(), units(3, 19, 7)
        genuine = retained.core.framed_digest
        for late in (False, True):
            for change in (None, "widen", "float"):
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits(
                    max_input_bytes=64 * 1024 * 1024 - 100))
                work.charge(hashes=3, input_bytes=19, json_nodes=7)
                entering, changed = work.limits, []
                original_bytes = entering.max_input_bytes
                target = TRANSITION_SCHEMA if late else BUNDLE_SCHEMA

                def digest(domain, *frames):
                    result = genuine(domain, *frames)
                    if domain == target and not changed:
                        changed.append(True)
                        if change is not None:
                            object.__setattr__(entering, "max_input_bytes",
                                original_bytes + 1 if change == "widen" else float(original_bytes))
                    return result

                with self.subTest(late=late, change=change), \
                        patch.object(retained.core, "framed_digest", side_effect=digest), \
                        patch.object(retained.mixed, "_verify", wraps=retained.mixed._verify) as actual:
                    if change is None:
                        derived = retained._derive_on_work(work=work, **inputs)
                        self.assert_documents(fixture, derived.retained)
                    else:
                        with self.assertRaisesRegex(retained.RevocationProofBundleError, "entering limits"):
                            retained._derive_on_work(work=work, **inputs)
                self.assertEqual((changed, actual.call_count), ([True], 1))
                spent = expected["total"]
                if change is not None and not late:
                    spent = {name: value - expected["finalization"][name] for name, value in spent.items()}
                self.assertEqual(observed_units(work.metrics), add_units(prior, spent))
                self.assertIs(work.limits, entering)
                self.assertFalse(hasattr(work, "_revocation_packaging_owner"))
                # Unwind restores identity, not externally corrupted values;
                # failed work is terminal and is not reused by this control.
                self.assertEqual(entering.max_input_bytes,
                    original_bytes + 1 if change == "widen" else original_bytes)
                self.assertIs(type(entering.max_input_bytes), float if change == "float" else int)


if __name__ == "__main__":
    unittest.main()
