#!/usr/bin/env python3
"""Private shared-ledger generation through the real revocation recipe.

Callers explicitly supply an owned argument/evidence graph and an actual work
object. Independent source documents and work arithmetic describe the expected
program. All observers delegate actual code; no successful verifier is mocked.
This source-only fixture claims neither full-graph prehash ownership nor
assertion/clock/root authority, kernel execution or planner activation.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_audit_capacity as capacity
from serverware import authority_contract
from serverware import authority_query_read_work as accounting
from serverware import authority_transition_core as core
from serverware import authority_transition_webauthn as candidate
import test_authority_revocation_query_program as recipe_oracle


OPERATION = recipe_oracle.OPERATION


def wire(value, *, ascii=True):
    return json.dumps(value, ensure_ascii=ascii, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii" if ascii else "utf-8")


def graph_nodes(value):
    if type(value) is dict:
        return 1 + sum(1 + graph_nodes(child) for child in value.values())
    if type(value) in (tuple, list):
        return 1 + sum(graph_nodes(child) for child in value)
    return 1


class ExpectedWork:
    """Literal work-unit arithmetic, with no production meter or observed totals."""

    def __init__(self):
        self.hash_work = self.input_bytes = self.json_nodes = 0

    def graph(self, value, *, bytes_passes=2, node_passes=2, ascii=True):
        self.input_bytes += bytes_passes * len(wire(value, ascii=ascii))
        self.json_nodes += node_passes * graph_nodes(value)

    def utf8(self, value):
        self.input_bytes += 2 * len(value.encode("utf-8"))
        self.json_nodes += 2

    def profile(self, index_id):
        descriptor = recipe_oracle.complete_oracle.index_oracle.descriptor(index_id)
        self.graph(descriptor, ascii=False)
        self.hash_work += 1

    def tuple(self):
        return self.hash_work, self.input_bytes, self.json_nodes


class GenerationFixture:
    def __init__(self, values=None, *, same_signer=False):
        self.values = copy.deepcopy(recipe_oracle.source_values() if values is None else values)
        self.signer = self.values["record_id"] if same_signer else "separate-signer"
        self.challenge = "assertion-challenge"
        self.inputs = {"arguments": recipe_oracle.arguments(self.values),
            "cutoff_us": recipe_oracle.CUTOFF_US, "request_digest": recipe_oracle.REQUEST_DIGEST,
            "evidence": {"credentialRecordId": self.signer, "challengeId": self.challenge}}

    @property
    def audit_count(self):
        return len(self.values["control_plane_approval_ids"]) + int(self.values["audit_event"] is not None)

    def expected(self):
        return recipe_oracle.expected_program(self.values, evidence=True, framework=True,
            signer=self.signer, challenge=self.challenge)

    def owned(self):
        return copy.deepcopy(self.inputs)


def expected_work(fixture):
    """Enumerate declared source-value passes using independent literal graphs.

    This oracle invokes no production preparation, constructor, profile or
    meter. Fixed bounded query-object scaffolding is not a JSON work unit.
    Success pays all twenty constructors; a denied reservation gets no refund.
    """
    expected = ExpectedWork()
    values = fixture.values
    intent = fixture.inputs["arguments"]["businessIntent"]

    # Actual semantic-field copy and actual prepare_revocation_input copy.
    expected.graph(fixture.inputs["arguments"])
    expected.graph(values)
    for name in ("record_id", "actor_id"):
        expected.utf8(values[name])
    if values["reason"] is not None:
        expected.utf8(values["reason"])
    if values["audit_event"] is not None:
        expected.graph(values["audit_event"], bytes_passes=4, node_passes=4)
    for name in recipe_oracle.HINTS:
        for item in values[name]:
            expected.utf8(item)
        # Set/sorted/list copies and BOTH comparison operands, each 2L/2N.
        expected.graph(values[name], bytes_passes=10, node_passes=10)
    expected.graph(values)  # genuine semantic canonicalization

    # Intent scan, filtered copy, and real encode/decode/loads normalization.
    expected.graph(values, bytes_passes=8, node_passes=7)
    expected.graph(intent, bytes_passes=4, node_passes=4)

    # Every bind really traverses every hint list, including unrelated roles.
    for _ in range(5):
        expected.utf8(values["record_id"])
        for name in recipe_oracle.HINTS:
            for item in values[name]:
                expected.utf8(item)
            # Tuple/set/sorted/final tuple + both comparison operands.
            expected.graph(values[name], bytes_passes=12, node_passes=12)

    # Initial bind + business close + capacity snapshot + capacity close.
    for _ in range(4):
        for role, _, index_id, _ in recipe_oracle.complete_oracle.ROLE_SPECS:
            selector = recipe_oracle.complete_oracle.selector_for(role,
                record_id=values["record_id"], cutoff_us=fixture.inputs["cutoff_us"])
            pairs = tuple(sorted(selector.items()))
            for name, value in pairs:
                if type(value) is str:
                    expected.utf8(value)
                    if name != "status":
                        expected.utf8(value)
            expected.graph(pairs, bytes_passes=4, node_passes=4)
            expected.profile(index_id)

    expected.graph(values["control_plane_approval_ids"])
    subjects = [*values["control_plane_approval_ids"]]
    if values["audit_event"] is not None:
        subjects.append(None)
    for subject in subjects:
        label = "credential" if subject is None else "approval:" + subject
        expected.utf8(label)
        purpose = "webauthn-revocation-audit:" + hashlib.sha256(label.encode("utf-8")).hexdigest()
        expected.utf8(purpose)
        expected.graph({"schema": "serverware.policyAuthorityDeterministicIdentity/v1",
            "operation": OPERATION, "requestDigest": fixture.inputs["request_digest"],
            "purpose": purpose})
        expected.hash_work += 2
    expected.utf8(fixture.signer)
    expected.utf8(fixture.challenge)
    return expected


class RevocationQueryWorkTests(unittest.TestCase):
    def meter(self, **changes):
        return accounting._ValidationWork(accounting.QueryReadValidationLimits(**changes))

    def generate(self, fixture, *, work=None, **changes):
        work = self.meter() if work is None else work
        inputs = fixture.owned()
        inputs.update(changes)
        return candidate._revocation_query_program(**inputs, work=work), work

    def assert_program(self, program, fixture):
        self.assertIs(type(program), tuple)
        actual = recipe_oracle.documents(program)
        self.assertEqual(actual, fixture.expected())
        self.assertEqual(wire(actual), wire(fixture.expected()))

    def assert_work(self, work, expected):
        self.assertEqual((work.metrics.hash_work, work.metrics.input_bytes,
            work.metrics.json_nodes), expected.tuple())

    def exact_limits(self, expected):
        return {"max_hashes": expected.hash_work, "max_input_bytes": expected.input_bytes,
            "max_json_nodes": expected.json_nodes}

    def test_private_shared_worker_equals_independent_program_and_actual_public_composition(self):
        fixture = GenerationFixture()
        before = copy.deepcopy(fixture.inputs)
        program, work = self.generate(fixture)
        public = capacity.add_capacity_query(OPERATION,
            candidate.WebAuthnCredentialRevokeKernel().queries_with_evidence_at_cutoff(**fixture.owned()))
        self.assertEqual(program, public)
        self.assert_program(program, fixture)
        self.assertEqual(fixture.inputs, before)
        self.assertEqual(work.metrics.hash_work, 20 + 2 * fixture.audit_count)

    def test_no_audits_and_same_signer_keep_all_roles_and_the_actual_framework_query(self):
        values = recipe_oracle.source_values(**{field: [] for field in recipe_oracle.HINTS}, audit_event=None)
        fixture = GenerationFixture(values, same_signer=True)
        program, work = self.generate(fixture)
        self.assert_program(program, fixture)
        self.assertEqual(len(program), 8)
        self.assertEqual(work.metrics.hash_work, 20)
        self.assertEqual(program[-1].absent_key, {"aggregate_id": recipe_oracle.counter_identity()})
        self.assertFalse(any(query.table == "metadata_audit_outbox" for query in program))

    def test_maximum_33_audits_reaches_42_real_declarations_without_new_allowances(self):
        values = recipe_oracle.source_values(**{field: [] for field in recipe_oracle.HINTS})
        values["control_plane_approval_ids"] = [f"approval-{ordinal:02d}" for ordinal in range(32)]
        fixture = GenerationFixture(values)
        program, work = self.generate(fixture)
        self.assert_program(program, fixture)
        self.assertEqual((fixture.audit_count, len(program), work.metrics.hash_work), (33, 42, 86))

    def test_unicode_audit_payload_remains_lossless_under_actual_intent_normalization(self):
        values = recipe_oracle.source_values(audit_event={"雪-key": [True, None, -7,
            "😀\t\n\"\\"], "nested": {"fractionless": 17, "text": "é"}})
        fixture = GenerationFixture(values)
        actual_loads = json.loads
        with patch.object(json, "loads", wraps=actual_loads) as parsed:
            program, _ = self.generate(fixture)
        self.assertEqual(parsed.call_count, 1)
        self.assertEqual(actual_loads(parsed.call_args.args[0]), fixture.values)
        self.assert_program(program, fixture)

    def test_actual_sha_count_is_20_profiles_plus_two_hashes_per_audit(self):
        cases = (recipe_oracle.source_values(control_plane_approval_ids=[], audit_event=None),
                 recipe_oracle.source_values(audit_event=None), recipe_oracle.source_values())
        actual_sha = hashlib.sha256
        for values in cases:
            fixture = GenerationFixture(values)
            with self.subTest(audits=fixture.audit_count):
                with patch.object(hashlib, "sha256", wraps=actual_sha) as hashes:
                    program, work = self.generate(fixture)
                self.assertEqual((hashes.call_count, work.metrics.hash_work),
                                 (20 + 2 * fixture.audit_count,) * 2)
                self.assert_program(program, fixture)

    def test_real_generation_and_capacity_workers_are_called_without_result_substitution(self):
        fixture = GenerationFixture()
        actual_capacity = capacity.add_capacity_query
        actual_uuid = core._deterministic_uuid
        actual_intent = authority_contract._synthesize_business_intent
        actual_canonical = core.canonical_bytes
        actual_loads = json.loads
        with patch.object(capacity, "add_capacity_query", wraps=actual_capacity) as capacities, \
                patch.object(core, "_deterministic_uuid", wraps=actual_uuid) as identities, \
                patch.object(authority_contract, "_synthesize_business_intent", wraps=actual_intent) as intents, \
                patch.object(core, "canonical_bytes", wraps=actual_canonical) as canonicalizations, \
                patch.object(json, "loads", wraps=actual_loads) as loads:
            program, work = self.generate(fixture)
        self.assertEqual(capacities.call_count, 1)
        self.assertEqual(identities.call_count, fixture.audit_count)
        self.assertEqual(intents.call_count, 1)
        self.assertIs(intents.call_args.kwargs["work"], work)
        self.assertTrue(all(call.kwargs["work"] is work for call in identities.call_args_list))
        self.assertEqual(loads.call_count, 1)
        self.assertGreaterEqual(canonicalizations.call_count, fixture.audit_count + 1)
        self.assert_program(program, fixture)

    def test_full_independent_byte_node_hash_oracle_covers_source_variants(self):
        empty = recipe_oracle.source_values(**{field: [] for field in recipe_oracle.HINTS},
            audit_event=None, reason=None)
        maximum = copy.deepcopy(empty)
        maximum["control_plane_approval_ids"] = [f"approval-{i:02d}" for i in range(32)]
        maximum["audit_event"] = {"message": "雪😀\n"}
        unicode_values = recipe_oracle.source_values(record_id="clé-雪", actor_id="acteur-é",
            reason="révocation\n雪", control_plane_approval_ids=["approuvé-雪"],
            audit_event={"雪-key": [True, None, -17, {"value": "😀\t\"\\"}]})
        cases = (GenerationFixture(), GenerationFixture(same_signer=True),
            GenerationFixture(empty, same_signer=True), GenerationFixture(maximum),
            GenerationFixture(unicode_values))
        for fixture in cases:
            with self.subTest(audits=fixture.audit_count, signer=fixture.signer):
                expected = expected_work(fixture)
                program, work = self.generate(fixture)
                self.assert_work(work, expected)
                self.assert_program(program, fixture)
                self.assertEqual(expected.hash_work, 20 + 2 * fixture.audit_count)

    def test_independently_exact_quotas_succeed_and_each_minus_one_denies(self):
        fixture = GenerationFixture()
        expected = expected_work(fixture)
        limits = self.exact_limits(expected)
        program, work = self.generate(fixture, work=self.meter(**limits))
        self.assert_program(program, fixture)
        self.assert_work(work, expected)
        actual_sha = hashlib.sha256
        for field in limits:
            tightened = {**limits, field: limits[field] - 1}
            work = self.meter(**tightened)
            with self.subTest(field=field), patch.object(hashlib, "sha256", wraps=actual_sha) as hashes:
                with self.assertRaises(accounting.QueryReadWorkError):
                    self.generate(fixture, work=work)
            self.assertLessEqual(hashes.call_count, work.metrics.hash_work)
            self.assertLessEqual(work.metrics.hash_work, tightened["max_hashes"])
            self.assertLessEqual(work.metrics.input_bytes, tightened["max_input_bytes"])
            self.assertLessEqual(work.metrics.json_nodes, tightened["max_json_nodes"])

    def test_repeated_real_generation_uses_the_same_ledger_without_reset(self):
        fixture = GenerationFixture()
        expected = expected_work(fixture)
        work = self.meter(**{name: 2 * value for name, value in self.exact_limits(expected).items()})
        first, first_work = self.generate(fixture, work=work)
        second, second_work = self.generate(fixture, work=work)
        self.assertIs(first_work, work)
        self.assertIs(second_work, work)
        self.assertEqual(first, second)
        self.assert_program(second, fixture)
        self.assertEqual((work.metrics.hash_work, work.metrics.input_bytes, work.metrics.json_nodes),
                         tuple(2 * value for value in expected.tuple()))
        before = work.metrics
        with self.assertRaises(accounting.QueryReadWorkError):
            self.generate(fixture, work=work)
        self.assertEqual(work.metrics, before)

    def test_hash_quota_reservation_denies_before_unreserved_real_sha(self):
        fixture = GenerationFixture()
        expected = expected_work(fixture)
        actual_sha = hashlib.sha256
        for cap in (1, 5, expected.hash_work - 1):
            work = self.meter(max_hashes=cap)
            with self.subTest(cap=cap), patch.object(hashlib, "sha256", wraps=actual_sha) as hashes:
                with self.assertRaises(accounting.QueryReadWorkError):
                    self.generate(fixture, work=work)
            self.assertGreater(hashes.call_count, 0)
            self.assertLessEqual(hashes.call_count, work.metrics.hash_work)
            self.assertEqual(work.metrics.hash_work, cap)
            # Closure/capacity reserve a block before running it, with no refund.
            self.assertLess(hashes.call_count, expected.hash_work)

    def test_exhausted_byte_or_node_quota_denies_before_real_encoding_or_hash(self):
        fixture = GenerationFixture()
        actual_dumps, actual_loads, actual_sha = json.dumps, json.loads, hashlib.sha256
        for limit in ({"max_input_bytes": 1}, {"max_json_nodes": 1}):
            work = self.meter(**limit)
            with self.subTest(limit=limit), \
                    patch.object(json, "dumps", wraps=actual_dumps) as encodings, \
                    patch.object(json, "loads", wraps=actual_loads) as parsings, \
                    patch.object(hashlib, "sha256", wraps=actual_sha) as hashes:
                with self.assertRaises(accounting.QueryReadWorkError):
                    self.generate(fixture, work=work)
            self.assertEqual((encodings.call_count, parsings.call_count, hashes.call_count), (0, 0, 0))

    def test_genuine_intent_worker_accounts_scan_copy_and_real_json_roundtrip(self):
        fixture = GenerationFixture(recipe_oracle.source_values(audit_event={"雪": [True, None, 7]}))
        values = copy.deepcopy(fixture.values)
        expected = ExpectedWork()
        expected.graph(values, bytes_passes=8, node_passes=7)
        work = self.meter(max_hashes=1, max_input_bytes=expected.input_bytes,
                          max_json_nodes=expected.json_nodes)
        actual_canonical, actual_loads = authority_contract._canonical, json.loads
        with patch.object(authority_contract, "_canonical", wraps=actual_canonical) as encodings, \
                patch.object(json, "loads", wraps=actual_loads) as parsings:
            intent = authority_contract._synthesize_business_intent(OPERATION, values, work=work)
        self.assertEqual((encodings.call_count, parsings.call_count), (1, 1))
        self.assertEqual(intent, fixture.inputs["arguments"]["businessIntent"])
        self.assertIsNot(intent["arguments"], values)
        self.assertIsNot(intent["arguments"]["audit_event"], values["audit_event"])
        self.assert_work(work, expected)

    def test_genuine_audit_identity_accounts_utf8_purpose_and_uuid_document(self):
        subject = "approbation-雪"
        label = "approval:" + subject
        purpose = "webauthn-revocation-audit:" + hashlib.sha256(label.encode("utf-8")).hexdigest()
        document = {"schema": "serverware.policyAuthorityDeterministicIdentity/v1", "operation": OPERATION,
            "requestDigest": recipe_oracle.REQUEST_DIGEST, "purpose": purpose}
        expected = ExpectedWork()
        expected.utf8(label)
        expected.utf8(purpose)
        expected.graph(document)
        expected.hash_work = 2
        identity = recipe_oracle.audit_identity(recipe_oracle.REQUEST_DIGEST, subject)
        work = self.meter(**self.exact_limits(expected))
        actual_sha, actual_canonical = hashlib.sha256, core.canonical_bytes
        with patch.object(hashlib, "sha256", wraps=actual_sha) as hashes, \
                patch.object(core, "canonical_bytes", wraps=actual_canonical) as encodings:
            actual = candidate._audit_id(OPERATION, recipe_oracle.REQUEST_DIGEST, subject, work=work)
        self.assertEqual(actual, identity)
        self.assertEqual((hashes.call_count, encodings.call_count), (2, 1))
        self.assertEqual(encodings.call_args.args[0], document)
        self.assert_work(work, expected)

    def test_limits_are_exact_source_bounded_and_work_requires_the_real_private_type(self):
        ceilings = {"max_hashes": 8_000_000, "max_input_bytes": 64 * 1024 * 1024,
                    "max_json_nodes": 1_000_000}
        self.assertEqual(accounting.QueryReadValidationLimits(),
                         accounting.QueryReadValidationLimits(**ceilings))
        for field, ceiling in ceilings.items():
            for bad in (True, False, 0, -1, 1.0, "1", ceiling + 1):
                with self.subTest(field=field, bad=bad), self.assertRaises(accounting.QueryReadWorkError):
                    accounting.QueryReadValidationLimits(**{field: bad})
        limits = accounting.QueryReadValidationLimits()
        with self.assertRaises(FrozenInstanceError):
            limits.max_hashes = 1
        bypassed = object.__new__(accounting.QueryReadValidationLimits)
        for field, value in ceilings.items():
            object.__setattr__(bypassed, field, True if field == "max_hashes" else value)
        with self.assertRaises(accounting.QueryReadWorkError):
            accounting._ValidationWork(bypassed)

        class WorkSubclass(accounting._ValidationWork):
            pass

        fixture = GenerationFixture()
        program, work = self.generate(fixture)
        for bad in (None, {}, work.metrics, program, WorkSubclass(limits)):
            with self.subTest(kind=type(bad)), self.assertRaises(accounting.QueryReadWorkError):
                # Bypass the convenience generate() helper: None must reach
                # the actual private entrypoint, not request a fresh meter.
                candidate._revocation_query_program(**fixture.owned(), work=bad)
        with self.assertRaises(FrozenInstanceError):
            work.metrics.hash_work = 0

    def test_changed_business_intent_is_compared_after_actual_normalization_before_hashing(self):
        fixture = GenerationFixture()
        owned = fixture.owned()
        supplied = owned["arguments"]["businessIntent"]
        supplied["arguments"]["reason"] = "changed supplied intent"
        work = self.meter()
        actual_compare = work.prepare_comparison
        actual_loads, actual_sha, actual_capacity = json.loads, hashlib.sha256, capacity.add_capacity_query
        with patch.object(work, "prepare_comparison", wraps=actual_compare) as comparisons, \
                patch.object(json, "loads", wraps=actual_loads) as parsings, \
                patch.object(hashlib, "sha256", wraps=actual_sha) as hashes, \
                patch.object(capacity, "add_capacity_query", wraps=actual_capacity) as capacities:
            with self.assertRaisesRegex(core.TransitionKernelError, "business intent changed"):
                candidate._revocation_query_program(**owned, work=work)
        self.assertEqual((parsings.call_count, hashes.call_count, capacities.call_count), (1, 0, 0))
        self.assertEqual(comparisons.call_args.args,
            (supplied, fixture.inputs["arguments"]["businessIntent"]))
        # Both full operands are reserved even though equality can stop at reason.
        self.assertGreaterEqual(work.input_bytes,
            2 * (len(wire(supplied)) + len(wire(fixture.inputs["arguments"]["businessIntent"]))))
        self.assertEqual(work.hash_work, 0)

    def test_real_source_guards_remain_fail_closed_under_metering(self):
        fixture = GenerationFixture()
        cases = []
        for cutoff in (True, "1", -(2**63) - 1, 2**63):
            cases.append(({"cutoff_us": cutoff}, core.TransitionKernelError))
        cases.extend((({"evidence": {"credentialRecordId": "", "challengeId": fixture.challenge}},
                       core.TransitionKernelError),
                      ({"evidence": {"credentialRecordId": fixture.signer, "challengeId": None}},
                       accounting.QueryReadWorkError),
                      ({"request_digest": "not-a-digest"}, core.TransitionKernelError)))
        invalid_values = (
            recipe_oracle.source_values(source="automatic"),
            recipe_oracle.source_values(approval_grant_ids=["z", "a"]),
            recipe_oracle.source_values(oidc_session_ids=[f"session-{i:02d}" for i in range(33)]),
            recipe_oracle.source_values(reason="x" * 16_385),
        )
        cases.extend(({"arguments": recipe_oracle.arguments(values)}, core.TransitionKernelError)
                     for values in invalid_values)
        for changes, error in cases:
            with self.subTest(changes=tuple(changes)), self.assertRaises(error):
                self.generate(fixture, **changes)
        for bad_arguments in ({}, {**fixture.inputs["arguments"], "unexpected": 1}):
            with self.assertRaises(core.TransitionKernelError):
                self.generate(fixture, arguments=bad_arguments)

    def test_repeated_large_admitted_audit_values_exhaust_one_actual_64mib_ledger(self):
        values = recipe_oracle.source_values(control_plane_approval_ids=[],
            audit_event={"padding": "x" * (1024 * 1024)})
        fixture = GenerationFixture(values)
        expected = expected_work(fixture)
        self.assertLess(len(wire(values["audit_event"])), 2 * 1024 * 1024)
        # Independent totals establish two successful generations and a third
        # rejection under the UNCHANGED source ceiling, not a lowered constant.
        self.assertLess(2 * expected.input_bytes, 64 * 1024 * 1024)
        self.assertGreater(3 * expected.input_bytes, 64 * 1024 * 1024)
        work = self.meter()
        for _ in range(2):
            program, same_work = self.generate(fixture, work=work)
            self.assertIs(same_work, work)
            self.assert_program(program, fixture)
        self.assertEqual(work.input_bytes, 2 * expected.input_bytes)
        self.assertEqual(work.json_nodes, 2 * expected.json_nodes)
        with self.assertRaises(accounting.QueryReadWorkError):
            self.generate(fixture, work=work)
        self.assertLessEqual(work.input_bytes, 64 * 1024 * 1024)
        self.assertGreater(work.input_bytes, 2 * expected.input_bytes)

    def test_generated_declarations_and_metrics_are_not_authorization_or_owned_input_tokens(self):
        values = recipe_oracle.source_values(**{field: [] for field in recipe_oracle.HINTS}, audit_event=None)
        fixture = GenerationFixture(values, same_signer=True)
        actual_transition = candidate.WebAuthnCredentialRevokeKernel.transition
        with patch.object(candidate.WebAuthnCredentialRevokeKernel, "transition", wraps=actual_transition) as kernels:
            program, work = self.generate(fixture, request_digest="unused-with-zero-audits")
        self.assertEqual(kernels.call_count, 0)
        self.assert_program(program, fixture)
        self.assert_work(work, expected_work(fixture))
        self.assertIs(type(program), tuple)
        self.assertIs(type(work.metrics), accounting.QueryReadValidationMetrics)
        self.assertFalse(hasattr(program, "verified"))
        # This component assumes owned arguments/evidence were supplied. It
        # neither snapshots a complete proof graph nor verifies these two IDs.
        self.assertEqual(set(fixture.inputs["evidence"]), {"credentialRecordId", "challengeId"})
        with self.assertRaises(accounting.QueryReadWorkError):
            candidate._revocation_query_program(**fixture.owned(), work=program)


if __name__ == "__main__":
    unittest.main()
