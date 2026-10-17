#!/usr/bin/env python3
"""Inactive v4 shape contracts over independent raw revocation fixtures.

The retained trees and receipt are genuine fixture constructions, but outer
digest claims and pins below are deliberately synthetic. Acceptance here is
only shape: no signature, proof, deadline, current-root or semantic authority.
All controls are authored source-only and unexecuted.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
from types import MappingProxyType
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_contract as source
from catchplate import authority_revocation_bundle_contract as retained
from catchplate import authority_revocation_plan_contract as contract
from catchplate import authority_webauthn_assertion as assertion
from authority_revocation_semantics_fixture import SemanticFixture


OPERATION = "webauthn.credential.revoke"
RESPONSE_SCHEMA = "catchplate.policyAuthorityPlannerResponse/v4"
PLAN_SCHEMA = "catchplate.policyAuthorityMeasuredPlan/v4"
SIGNED_SCHEMA = "catchplate.signedPolicyAuthorityMeasuredPlan/v4"
SNAPSHOT_DOMAIN = "catchplate.policyAuthoritySnapshot/v4"
FRAME_NAMES = ("operation", "operationId", "requestDigest", "queryManifestDigest",
    "authorityRootSetBeforeDigest", "authorizationProjectionDigest",
    "selectedBusinessRowsDigest", "mutationPlanDigest", "rootTransitionDigest")
PAYLOAD_FIELDS = {"schema", "measuredPlan", "typedRequest", "selectedBusinessRows",
    "mutationPlan", "queryMultiproofs", "queryMultiproofsDigest", "plannerTrace",
    "plannerTraceDigest", "authorizationProjection", "webauthnEvidence", "expectedResult",
    "expectedResultDigest", "plannerIdentity", "rootTransition", "revocationProofBundle"}
PLAN_FIELDS = {"schema", "plannerTransactionId", "operation", "operationId", "requestDigest",
    "capabilityId", "sourceRevision", "authoritySchemaVersion", "operationContractDigest",
    "operationManifestDigest", "handlerContractDigest", "queryManifestDigest",
    "selectedBusinessRowsDigest", "mutationPlanDigest", "workUnits", "authorityRootSetBeforeDigest",
    "authorizationProjectionDigest", "authoritySnapshotDigest", "rootTransitionDigest",
    "deadlineMonotonicNs", "deadlineEpochNs", "fence"}
IDENTITY_FIELDS = {"sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"}
PROJECTION_FIELDS = {"plannerTransactionId", "operation", "operationId", "requestDigest",
    "capabilityId", "authorizationReads", "sourceRows", "sourceHighWaterDigest",
    "approverPolicyDigest", "assertionEvidenceDigest", "verifierSessionIdentityDigest",
    "verifierMeasurementDigest", "verifierAttestationReceiptDigest", "createdAtEpochNs", "expiresAtEpochNs"}
DIGEST = "sha256:" + "1" * 64


class Text(str):
    pass


class Integer(int):
    pass


def payload_fixture(**variants):
    """Literal transport layout; no production shape builder or verified DTO."""
    fixture = SemanticFixture(**variants)
    inputs = fixture.bundle["inputs"]
    plan = {"schema": PLAN_SCHEMA, "plannerTransactionId": DIGEST,
        "operation": OPERATION, "operationId": fixture.operation_id,
        "requestDigest": fixture.request_digest, "capabilityId": fixture.receipt.capability_id,
        "sourceRevision": source.SOURCE_REVISION, "authoritySchemaVersion": 9,
        "operationContractDigest": DIGEST, "operationManifestDigest": DIGEST,
        "handlerContractDigest": DIGEST, "queryManifestDigest": DIGEST,
        "selectedBusinessRowsDigest": DIGEST, "mutationPlanDigest": DIGEST,
        "workUnits": fixture.work_units, "authorityRootSetBeforeDigest": DIGEST,
        "authorizationProjectionDigest": DIGEST, "authoritySnapshotDigest": DIGEST,
        "rootTransitionDigest": DIGEST, "deadlineMonotonicNs": 1,
        "deadlineEpochNs": 1, "fence": 1}
    authorization_tables = [root["table"] for root in inputs["authorizationBeforeRoots"]]
    rows = [{"table": row["table"], "selector": copy.deepcopy(row["key"]),
        "present": row["present"], "row": copy.deepcopy(row["row"]), "rowDigest": DIGEST}
        for row in inputs["selectedRows"] if row["table"] in authorization_tables]
    projection = {"plannerTransactionId": DIGEST, "operation": OPERATION,
        "operationId": fixture.operation_id, "requestDigest": fixture.request_digest,
        "capabilityId": fixture.receipt.capability_id, "authorizationReads": authorization_tables,
        "sourceRows": rows, "sourceHighWaterDigest": DIGEST, "approverPolicyDigest": None,
        "assertionEvidenceDigest": DIGEST, "verifierSessionIdentityDigest": DIGEST,
        "verifierMeasurementDigest": DIGEST, "verifierAttestationReceiptDigest": DIGEST,
        "createdAtEpochNs": 1, "expiresAtEpochNs": 1}
    trace_entries = [{"ordinal": number, "access": "read", "table": row["table"],
        "key": copy.deepcopy(row["key"])} for number, row in enumerate(inputs["selectedRows"])]
    return {"schema": RESPONSE_SCHEMA, "measuredPlan": plan,
        "typedRequest": copy.deepcopy(fixture.request),
        "selectedBusinessRows": copy.deepcopy(inputs["selectedRows"]),
        "mutationPlan": copy.deepcopy(inputs["mutations"]),
        "queryMultiproofs": copy.deepcopy(inputs["beforeProofs"]),
        "queryMultiproofsDigest": DIGEST,
        "plannerTrace": {"schema": "catchplate.policyAuthorityPlannerTrace/v1",
            "operation": OPERATION, "entries": trace_entries},
        "plannerTraceDigest": DIGEST, "authorizationProjection": projection,
        "webauthnEvidence": copy.deepcopy(fixture.receipt.evidence),
        "expectedResult": copy.deepcopy(fixture.kernel_expected["result"]),
        "expectedResultDigest": DIGEST, "plannerIdentity": {name: DIGEST for name in IDENTITY_FIELDS},
        "rootTransition": copy.deepcopy(fixture.transition),
        "revocationProofBundle": copy.deepcopy(fixture.bundle)}


class RevocationPlanContractTests(unittest.TestCase):
    def setUp(self):
        self.payload = payload_fixture()

    def deny(self, payload):
        with self.assertRaises(contract.RevocationPlanContractError):
            contract.validate_payload_shape(payload)

    def test_exact_literal_v4_shapes_domains_frames_and_source_ceilings(self):
        self.assertEqual(contract.PLANNER_RESPONSE_SCHEMA, RESPONSE_SCHEMA)
        self.assertEqual(contract.MEASURED_PLAN_SCHEMA, PLAN_SCHEMA)
        self.assertEqual(contract.SIGNED_MEASURED_PLAN_SCHEMA, SIGNED_SCHEMA)
        self.assertEqual(contract.SNAPSHOT_DOMAIN, SNAPSHOT_DOMAIN)
        self.assertEqual(contract.SNAPSHOT_FRAME_FIELDS, FRAME_NAMES)
        self.assertEqual(len(FRAME_NAMES), 9)
        self.assertEqual(contract.PAYLOAD_FIELDS, PAYLOAD_FIELDS)
        self.assertEqual(contract.MEASURED_PLAN_FIELDS, PLAN_FIELDS)
        self.assertEqual((len(PAYLOAD_FIELDS), len(PLAN_FIELDS)), (16, 22))
        self.assertEqual(contract.SIGNED_ENVELOPE_FIELDS, {"schema", "payload", "signatureBase64Url"})
        self.assertEqual(contract.AUTHORIZATION_PROJECTION_FIELDS, PROJECTION_FIELDS)
        self.assertEqual(contract.IDENTITY_FIELDS, IDENTITY_FIELDS)
        self.assertEqual((contract.MAX_PAYLOAD_BYTES, contract.MAX_JSON_NODES, contract.MAX_JSON_DEPTH),
                         (64 * 1024 * 1024, 1_000_000, 128))
        self.assertEqual((contract.MAX_SELECTED_ROWS, contract.MAX_MUTATIONS, contract.MAX_WORK_UNITS),
                         (193, 137, 2050))
        self.assertEqual(contract.MAX_TRACE_ENTRIES, 4165)
        self.assertEqual(contract.EVIDENCE_FIELDS, assertion.EVIDENCE_FIELDS)

    def test_genuine_raw_fixture_variants_and_json_roundtrip_are_shape_valid(self):
        for variants in ({}, {"separate_signer": True}, {"include_audit": False, "approval": False},
                         {"pending_count": 2}):
            with self.subTest(variants=variants):
                payload = payload_fixture(**variants)
                decoded = json.loads(json.dumps(payload, ensure_ascii=True, allow_nan=False))
                self.assertIsNone(contract.validate_payload_shape(decoded))
                self.assertEqual(decoded, payload)
                self.assertEqual(len(payload["rootTransition"]), 14)
                self.assertEqual(len(payload["rootTransition"]["primaryTransition"]), 7)

    def test_shape_calls_no_hash_encoder_parser_clock_or_proof_verifier(self):
        payload = self.payload
        with patch.object(hashlib, "sha256", side_effect=AssertionError("shape hashed")), \
                patch.object(json, "dumps", side_effect=AssertionError("shape encoded")), \
                patch.object(json, "loads", side_effect=AssertionError("shape parsed")), \
                patch("time.time_ns", side_effect=AssertionError("shape sampled time")), \
                patch("time.monotonic_ns", side_effect=AssertionError("shape sampled time")), \
                patch.object(retained.primary_wire, "verify_primary_root_transition",
                    side_effect=AssertionError("shape verified proof")):
            self.assertIsNone(contract.validate_payload_shape(payload))

    def test_top_level_closure_exact_types_and_v3_are_not_auto_upgraded(self):
        for changed in (None, [], MappingProxyType(self.payload), {**self.payload, "unknown": None},
                        {name: value for name, value in self.payload.items() if name != "revocationProofBundle"},
                        {**self.payload, "schema": "catchplate.policyAuthorityPlannerResponse/v3"}):
            with self.subTest(value_type=type(changed)):
                self.deny(changed)
        for name in ("schema", "operation", "sourceRevision"):
            changed = copy.deepcopy(self.payload)
            changed["measuredPlan"][name] = Text(changed["measuredPlan"][name])
            self.deny(changed)

    def test_measured_plan_closure_revoke_source_identity_and_digest_scalar_types(self):
        for field, value in (("schema", "catchplate.policyAuthorityMeasuredPlan/v3"),
                ("operation", "webauthn.counter.cas"), ("sourceRevision", "old-source"),
                ("authoritySchemaVersion", True), ("authoritySchemaVersion", 10),
                ("operationId", "sha256:" + "A" * 64), ("requestDigest", DIGEST.encode()),
                ("capabilityId", Text(DIGEST))):
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(self.payload)
                changed["measuredPlan"][field] = value
                self.deny(changed)
        with self.assertRaises(contract.RevocationPlanContractError):
            contract.validate_measured_plan_shape({**self.payload["measuredPlan"], "extra": None})

    def test_deadline_fence_and_work_bounds_are_exact_but_not_freshness_authority(self):
        plan = self.payload["measuredPlan"]
        for name in ("deadlineMonotonicNs", "deadlineEpochNs", "fence"):
            for value in (0, -1, True, Integer(1), 2**63, 1.0, "1"):
                with self.subTest(field=name, value=value), self.assertRaises(contract.RevocationPlanContractError):
                    contract.validate_measured_plan_shape({**plan, name: value})
            self.assertIsNone(contract.validate_measured_plan_shape({**plan, name: 2**63 - 1}))
        for value in (0, 2051, True, Integer(1)):
            with self.assertRaises(contract.RevocationPlanContractError):
                contract.validate_measured_plan_shape({**plan, "workUnits": value})
        self.assertIsNone(contract.validate_measured_plan_shape({**plan, "workUnits": 2050}))
        # A deadline of one is intentionally stale; no clock is sampled here.
        self.assertIsNone(contract.validate_measured_plan_shape(plan))

    def test_identity_is_exact_three_digest_claims_without_pin_comparison(self):
        identity = self.payload["plannerIdentity"]
        for changed in ({**identity, "key": DIGEST}, {}, MappingProxyType(identity),
                        {**identity, "measurementDigest": Text(DIGEST)},
                        {**identity, "measurementDigest": DIGEST + "0"}):
            with self.assertRaises(contract.RevocationPlanContractError):
                contract.validate_identity_shape(changed)
        self.assertIsNone(contract.validate_identity_shape({name: "sha256:" + "f" * 64 for name in identity}))

    def test_outer_array_counts_deny_before_retained_graph_traversal(self):
        for name, maximum in (("selectedBusinessRows", 193), ("queryMultiproofs", 193),
                              ("mutationPlan", 137)):
            for bad in ([None] * (maximum + 1), tuple(self.payload[name]), MappingProxyType({})):
                changed = {**self.payload, name: bad}
                with self.subTest(field=name), patch.object(retained, "validate_bundle_shape",
                        wraps=retained.validate_bundle_shape) as delegate:
                    self.deny(changed)
                    self.assertEqual(delegate.call_count, 0)
        changed = {**self.payload, "plannerTrace": {"schema": "unused", "operation": OPERATION,
                                                   "entries": [None] * 4166}}
        with patch.object(retained, "validate_bundle_shape", wraps=retained.validate_bundle_shape) as delegate:
            self.deny(changed)
            self.assertEqual(delegate.call_count, 0)

    def test_existing_bundle_and_mixed_transition_shape_workers_are_real_delegates(self):
        with patch.object(retained, "validate_bundle_shape", wraps=retained.validate_bundle_shape) as bundle, \
                patch.object(retained, "validate_transition_shape", wraps=retained.validate_transition_shape) as transition:
            self.assertIsNone(contract.validate_payload_shape(self.payload))
        self.assertEqual((bundle.call_count, transition.call_count), (1, 1))
        self.assertIs(bundle.call_args.args[0], self.payload["revocationProofBundle"])
        self.assertIs(transition.call_args.args[0], self.payload["rootTransition"])
        changed = copy.deepcopy(self.payload)
        changed["rootTransition"] = changed["rootTransition"]["primaryTransition"]
        self.deny(changed)
        changed = copy.deepcopy(self.payload)
        changed["rootTransition"]["duplicatePrimary"] = changed["rootTransition"]["primaryTransition"]
        self.deny(changed)

    def test_retained_nested_closure_and_limits_propagate_as_plan_contract_errors(self):
        for target in ("revocationProofBundle", "rootTransition"):
            changed = copy.deepcopy(self.payload)
            changed[target]["extra"] = None
            with self.assertRaises(contract.RevocationPlanContractError) as caught:
                contract.validate_payload_shape(changed)
            self.assertIsInstance(caught.exception.__cause__, retained.RevocationBundleContractError)
        changed = copy.deepcopy(self.payload)
        changed["revocationProofBundle"]["inputs"]["queryReads"] *= 43
        self.deny(changed)
        changed = copy.deepcopy(self.payload)
        changed["rootTransition"]["metrics"]["hashWork"] += 1
        self.deny(changed)

    def test_selected_mutation_and_proof_wrappers_reuse_closed_raw_shapes(self):
        for name in ("selectedBusinessRows", "mutationPlan", "queryMultiproofs"):
            changed = copy.deepcopy(self.payload)
            changed[name][0]["extra"] = None
            self.deny(changed)
        changed = copy.deepcopy(self.payload)
        changed["selectedBusinessRows"][0]["present"] = 1
        self.deny(changed)
        changed = copy.deepcopy(self.payload)
        changed["selectedBusinessRows"][0]["contractSelector"] = "discard-me"
        self.deny(changed)
        changed = copy.deepcopy(self.payload)
        changed["mutationPlan"][0]["operation"] = "UPSERT"
        self.deny(changed)
        changed = copy.deepcopy(self.payload)
        changed["queryMultiproofs"][0]["siblings"][0]["childDigests"].pop()
        self.deny(changed)

    def test_typed_request_preserves_real_arguments_and_rejects_alternate_operation_shape(self):
        for name, value in (("operation", "webauthn.registration.finalize"),
                ("handler", "anything"), ("schema", "catchplate.policyAuthorityV9Request/v2"),
                ("arguments", MappingProxyType({})), ("arguments", {str(n): n for n in range(65)})):
            changed = copy.deepcopy(self.payload)
            changed["typedRequest"][name] = value
            self.deny(changed)
        changed = copy.deepcopy(self.payload)
        changed["typedRequest"]["arguments"]["record_id"] = "different-claim"
        # Full request/intent/bundle consistency belongs to actual semantics.
        self.assertIsNone(contract.validate_payload_shape(changed))
        changed["typedRequest"]["arguments"] = {str(n): n for n in range(64)}
        self.assertIsNone(contract.validate_payload_shape(changed))

    def test_projection_exact_fields_source_rows_optional_policy_and_integer_types(self):
        for name, value in (("sourceRows", [None] * 65), ("authorizationReads", ["table"] * 65),
                ("createdAtEpochNs", True), ("expiresAtEpochNs", 2**63),
                ("assertionEvidenceDigest", None), ("approverPolicyDigest", "not-a-digest")):
            changed = copy.deepcopy(self.payload)
            changed["authorizationProjection"][name] = value
            self.deny(changed)
        changed = copy.deepcopy(self.payload)
        changed["authorizationProjection"]["sourceRows"] = [{"table": "webauthn_credentials",
            "selector": {"id": "x"}, "present": False, "row": None, "rowDigest": DIGEST}]
        changed["authorizationProjection"]["approverPolicyDigest"] = DIGEST
        self.assertIsNone(contract.validate_payload_shape(changed))
        changed["authorizationProjection"]["sourceRows"][0]["extra"] = 0
        self.deny(changed)

    def test_assertion_scalar_contract_is_closed_but_does_not_verify_signature_or_flags(self):
        for name, value in (("userPresent", 1), ("counter", True), ("counter", 2**63),
                ("origin", "x" * 4097), ("challengeDigest", None),
                ("clientDataJSONBase64url", "AA="), ("verifierSignatureBase64url", "A" * 85)):
            changed = copy.deepcopy(self.payload)
            changed["webauthnEvidence"][name] = value
            self.deny(changed)
        changed = copy.deepcopy(self.payload)
        changed["webauthnEvidence"].update(userPresent=False, userVerified=False, flags=0,
            verifierSignatureBase64url="A" * 86)
        self.assertIsNone(contract.validate_payload_shape(changed))

    def test_trace_shape_preserves_bounded_opaque_markers_without_permission_authority(self):
        entry = {"ordinal": 0, "access": "read", "table": "unknown_table", "key": {"profile": "opaque"}}
        changed = copy.deepcopy(self.payload)
        changed["plannerTrace"]["entries"] = [entry]
        self.assertIsNone(contract.validate_payload_shape(changed))
        for name, value in (("ordinal", True), ("ordinal", 1), ("access", "delete"),
                ("table", Text("table")), ("key", []), ("key", {str(n): n for n in range(33)})):
            invalid = copy.deepcopy(changed)
            invalid["plannerTrace"]["entries"][0][name] = value
            self.deny(invalid)
        changed["plannerTrace"]["entries"] = [{"ordinal": 0, "access": "write", "table": "table", "key": None}]
        self.deny(changed)

    def test_signed_envelope_exact_three_fields_and_canonical_signature_tail_bits(self):
        envelope = {"schema": SIGNED_SCHEMA, "payload": self.payload, "signatureBase64Url": "A" * 86}
        self.assertIsNone(contract.validate_signed_envelope_shape(envelope))
        for bad in ("A" * 85, "A" * 87, "A" * 85 + "B", "A" * 85 + "_",
                    "A" * 85 + "=", b"A" * 86, Text("A" * 86)):
            with self.assertRaises(contract.RevocationPlanContractError):
                contract.validate_signed_envelope_shape({**envelope, "signatureBase64Url": bad})
        for last in "AQgw":
            self.assertIsNone(contract.validate_signed_envelope_shape({**envelope,
                "signatureBase64Url": "A" * 85 + last}))
        for changed in ({**envelope, "schema": "catchplate.signedPolicyAuthorityMeasuredPlan/v3"},
                        {**envelope, "verified": True}, MappingProxyType(envelope)):
            with self.assertRaises(contract.RevocationPlanContractError):
                contract.validate_signed_envelope_shape(changed)

    def test_opaque_query_strings_generic_result_and_callers_graph_are_not_rewritten(self):
        changed = copy.deepcopy(self.payload)
        record = changed["revocationProofBundle"]["inputs"]["queryReads"][0]
        record["declaredQueryJson"] = "not parsed JSON"
        record["resolvedQueryJson"] = "\u2603 opaque text"
        original = copy.deepcopy(changed)
        with patch.object(json, "loads", side_effect=AssertionError("query JSON parsed")):
            self.assertIsNone(contract.validate_payload_shape(changed))
        self.assertEqual(changed, original)
        for value in (None, False, 1, "", [], {"value": [None, True, -1]}, {"x" * 129: "generic result key"}):
            self.assertIsNone(contract.validate_payload_shape({**changed, "expectedResult": value}))
        for bad in (1.0, float("nan"), (), MappingProxyType({}), b"{}"):
            self.deny({**changed, "expectedResult": bad})

    def test_shape_has_no_verified_result_trust_context_or_v3_activation_argument(self):
        for keyword in ("verified", "expected_identity", "expected_before", "now_epoch_ns", "limits"):
            with self.assertRaises(TypeError):
                contract.validate_payload_shape(self.payload, **{keyword: None})
        source_text = (ROOT / "catchplate/authority_revocation_plan_contract.py").read_text()
        self.assertNotIn("import authority_planner", source_text)
        self.assertNotIn("import authority_transition_registry", source_text)
        planner_text = (ROOT / "catchplate/authority_planner.py").read_text()
        self.assertIn('PLANNER_RESPONSE_SCHEMA = "catchplate.policyAuthorityPlannerResponse/v3"', planner_text)
        self.assertIn('MEASURED_PLAN_SCHEMA = "catchplate.policyAuthorityMeasuredPlan/v3"', planner_text)
        self.assertIn('"complete planning requires the successor retained-evidence protocol"', planner_text)


if __name__ == "__main__":
    unittest.main()
