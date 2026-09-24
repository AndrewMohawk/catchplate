#!/usr/bin/env python3
"""Authenticate the existing original v4 plan and replay independent inputs.

Deterministic keys and independent row/tree recipes supply genuine signatures
and retained proof work. The actual two-read root worker runs against a bounded
SQL responder, not PostgreSQL admission. No active planner registry, trusted
result token, persistence receipt, current-root authority or physical clock
provenance is supplied or claimed. The bootstrap authenticates a planner claim;
the same original envelope still undergoes complete retained replay.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_handoff as handoff
from serverware import authority_revocation_retention as retention
import test_authority_revocation_plan as oracle
import test_authority_revocation_retention as record_oracle
import test_authority_revocation_wire as wire_oracle
import test_authority_revocation_observed as observed_oracle
import test_authority_revocation_roots as root_oracle
import test_authority_index_heads as head_oracle
import test_authority_indexed_mutation as write_oracle
import test_authority_index_join as profile_oracle
import test_authority_index_range as tree_oracle


SIGNED_SCHEMA = "serverware.signedPolicyAuthorityMeasuredPlan/v4"
PHASES = ("capture", "transport", "authentication", "bindings", "projection", "replay")
READ_IDS = ("webauthn_control_approval_approved", "webauthn_grant_approver_active",
    "webauthn_publication_status", "webauthn_registration_unused_global", "webauthn_session_credential_status")
WRITE_PROFILES = {
    "webauthn_credentials": ("webauthn_credential_id", "webauthn_credential_live_trust", "webauthn_credential_user_history"),
    "webauthn_challenges": ("webauthn_registration_unused_global", "webauthn_registration_unused_user"),
    "oidc_browser_sessions": ("webauthn_session_credential_status",),
    "approval_grants": ("webauthn_grant_approver_active",),
    "control_plane_approvals": ("webauthn_control_approval_approved",),
    "metadata_audit_outbox": (), "policy_authority_bounded_aggregate_states": (),
}


def work(limits=None):
    return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))


def units(meter):
    return meter.hash_work, meter.input_bytes, meter.json_nodes


def full_root_rows(plan):
    """All populations come from the independent tree fixture, not plan claims."""
    semantic = plan.semantic
    primary = root_oracle.primary_rows()
    for row in primary:
        root = semantic.read_write.read.trees[row["table_name"]].root
        row.update(root_revision=root.root_revision, root_digest=root.root_digest,
            leaf_count=root.leaf_count)
    counted = head_oracle.source_rows()
    for row in counted:
        profile = profile_oracle.expected_profile(row["index_id"])
        leaves = [write_oracle.image_leaf(profile, item,
            semantic.read_write.expiry_before.get(item["id"])) for item in semantic.rows[profile.table]]
        tree = tree_oracle.IndependentIndex([leaf for leaf in leaves if leaf is not None], profile)
        row.update(index_revision=29, root_digest=tree.root.digest, leaf_count=tree.root.count)
    return primary, counted


class HandoffFixture:
    def __init__(self, **options):
        self.plan = oracle.PlanFixture(**options)
        self.primary, self.heads = full_root_rows(self.plan)
        self.acquisition = root_oracle.inventory_fixture(primary_values=self.primary, head_values=self.heads)
        self.inventory = root_oracle.acquire(self.acquisition)
        self.request = copy.deepcopy(self.plan.semantic.request)
        self.expected_context = oracle.production_context(self.plan)
        selected = set(READ_IDS)
        for mutation in self.plan.semantic.final_mutations:
            selected.update(WRITE_PROFILES[mutation["table"]])
        self.selected_ids = tuple(sorted(selected))
        independent_before = observed_oracle.expected_before(self.primary, self.heads, self.selected_ids)
        if self.expected_context["expectedBefore"] != independent_before:
            raise AssertionError("independent full populations do not match the genuine selected proof fixture")
        self.context = {name: copy.deepcopy(value) for name, value in self.expected_context.items()
            if name != "expectedBefore"}
        self.refresh_bytes()

    def refresh_bytes(self):
        self.raw = oracle.wire(self.plan.envelope)
        self.context_raw = oracle.wire(record_oracle.record_context(self.plan))

    def arguments(self):
        return {"envelope_bytes": self.raw, "evaluation_context_bytes": self.context_raw,
            "expected_request": self.request, "context": self.context, "root_inventory": self.inventory,
            "planner_public_key": self.plan.key.public_key(),
            "verifier_public_key": self.plan.semantic.receipt.key.public_key()}


def independent_work(fixture):
    """Literal new passes plus the existing independent genuine replay oracle."""
    plan, context = fixture.plan, fixture.context
    payload, measured = plan.payload, plan.payload["measuredPlan"]
    phases = {"capture": oracle.add(
        observed_oracle.copy_cost({"expectedRequest": fixture.request, "context": context}),
        observed_oracle.copy_cost(observed_oracle.capture_graph(fixture.primary, fixture.heads)))}
    phases["transport"] = oracle.add(wire_oracle.decoder_units(fixture.raw, plan.envelope),
        oracle.graph_cost(plan.envelope), (0, 2 * len(fixture.raw), 0), oracle.graph_cost(payload))
    payload_wire = oracle.wire(payload)
    message = oracle.framed(SIGNED_SCHEMA, payload_wire)
    phases["authentication"] = oracle.add((0, 416, 0),
        oracle.frame_cost(SIGNED_SCHEMA, (payload_wire,)), oracle.utf8_cost(message))
    expected_source = {
        "operationContractDigest": oracle.authority_contract.OPERATION_MANIFEST_DIGEST,
        "operationManifestDigest": oracle.authority_contract.OPERATION_MANIFEST_DIGEST,
        "handlerContractDigest": oracle.authority_contract.handler_contract_digest("webauthn.credential.revoke"),
        "queryManifestDigest": oracle.source_manifest_digest(),
        "operationId": fixture.request["operationId"], "requestDigest": fixture.request["requestDigest"],
    }
    identity = context["expectedVerifierIdentity"]
    expected_authorization = {
        "verifierSessionIdentityDigest": identity["sessionIdentityDigest"],
        "verifierMeasurementDigest": identity["measurementDigest"],
        "verifierAttestationReceiptDigest": identity["attestationReceiptDigest"],
        "approverPolicyDigest": context["expectedApproverPolicyDigest"],
        "createdAtEpochNs": context["reservedAtEpochNs"], "expiresAtEpochNs": context["deadlineEpochNs"],
    }
    pairs = ((payload["typedRequest"], fixture.request),
        (payload["plannerIdentity"], context["expectedPlannerIdentity"]),
        (measured["capabilityId"], context["expectedCapabilityId"]),
        (measured["plannerTransactionId"], context["expectedPlannerTransactionId"]),
        (measured["fence"], context["expectedFence"]),
        (measured["deadlineEpochNs"], context["deadlineEpochNs"]),
        (measured["deadlineMonotonicNs"], context["deadlineMonotonicNs"]),
        ({name: measured[name] for name in expected_source}, expected_source),
        ({name: payload["authorizationProjection"][name] for name in expected_authorization}, expected_authorization),
        (plan.semantic.cutoff_us, plan.semantic.cutoff_us))
    phases["bindings"] = oracle.add(*(oracle.canonical_comparison(left, right) for left, right in pairs))
    phases["projection"] = observed_oracle.copy_cost(fixture.expected_context)
    replay = record_oracle.independent_record_metrics(plan)
    phases["replay"] = replay["total"]
    prefix = oracle.add(*(phases[name] for name in PHASES[:-1]))
    total = oracle.add(prefix, replay["total"])
    peak = oracle.add(prefix, replay["admission"])
    return {**phases, "prefix": prefix, "total": total,
        "admission": tuple(max(left, right) for left, right in zip(total, peak))}


class RevocationHandoffTests(unittest.TestCase):
    def verify(self, fixture, *, meter=None, **changes):
        arguments = {**fixture.arguments(), **changes}
        return handoff._verify_observed_plan_handoff_on_work(work=work() if meter is None else meter, **arguments)

    def test_existing_signed_original_bytes_bootstrap_two_planner_signatures_and_one_real_replay(self):
        fixture, meter = HandoffFixture(approval=False, include_audit=False), work()
        events = []
        planner_key = oracle._CallbackPublicKey(fixture.plan.key.public_key(), lambda: events.append("planner"))
        verifier_key = oracle._CallbackPublicKey(fixture.plan.semantic.receipt.key.public_key(), lambda: events.append("assertion"))
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.semantics, "_verify", wraps=retention.plan.semantics._verify) as semantic, \
                patch.object(retention.plan.semantics.retained, "_compute_and_package",
                    wraps=retention.plan.semantics.retained._compute_and_package) as proof:
            actual = self.verify(fixture, meter=meter, planner_public_key=planner_key, verifier_public_key=verifier_key)
        self.assertEqual(events, ["planner", "planner", "assertion"])
        self.assertEqual((planner_key.calls, verifier_key.calls, replay.call_count, semantic.call_count, proof.call_count),
            (2, 1, 1, 1, 1))
        self.assertIs(replay.call_args.kwargs["work"], meter)
        self.assertIs(replay.call_args.kwargs["envelope_bytes"], fixture.raw)
        self.assertIs(replay.call_args.kwargs["evaluation_context_bytes"], fixture.context_raw)
        self.assertEqual((len(fixture.acquisition[0].calls), fixture.acquisition[4].returned_rows), (2, 18))
        self.assertEqual(actual.database_now, fixture.plan.semantic.database_now)
        self.assertIs(actual.database_now.tzinfo, timezone.utc)
        self.assertEqual(actual.expected_context, fixture.expected_context)
        self.assertEqual(actual.retained_record.envelope_bytes, fixture.raw)
        self.assertEqual(actual.retained_record.context_bytes, fixture.context_raw)
        self.assertEqual(actual.retained_record.payload_bytes, oracle.wire(fixture.plan.payload))
        header = record_oracle.record_header(fixture.plan, fixture.raw, fixture.context_raw)
        self.assertEqual(actual.retained_record.header, header)
        self.assertEqual(actual.retained_record.record_digest, oracle.framed(record_oracle.RECORD_SCHEMA, oracle.wire(header)))
        self.assertEqual((actual.metrics.planner_signature_attempts, actual.metrics.semantic_replays), (2, 1))
        expected = independent_work(fixture)
        for name in PHASES:
            self.assertEqual(oracle.units(getattr(actual.metrics, name)), expected[name], name)
        self.assertEqual(units(meter), expected["total"])
        self.assertEqual((actual.metrics.total_hashes, actual.metrics.total_input_bytes,
            actual.metrics.total_json_nodes), expected["total"])
        self.assertEqual(expected["prefix"][0], 1)
        with self.assertRaises(FrozenInstanceError):
            actual.database_now = fixture.plan.semantic.database_now + timedelta(microseconds=1)

    def test_source_profile_selection_uses_independent_values_for_genuine_effect_variants(self):
        # These are real revocation fixtures, including nonmember images and
        # an empty approval range. No invented read-only revocation is approved.
        for options in ({}, {"approval": False, "include_audit": False},
                {"separate_signer": True}, {"pending_count": 2}):
            fixture = HandoffFixture(**options)
            with self.subTest(options=options):
                actual = self.verify(fixture)
            self.assertEqual(actual.expected_context, fixture.expected_context)
            before = actual.expected_context["expectedBefore"]
            self.assertEqual((len(before["businessBeforeRoots"]), len(before["authorizationBeforeRoots"])), (7, 2))
            self.assertEqual(tuple(row["indexId"] for row in before["indexBeforeHeads"]), fixture.selected_ids)
            self.assertEqual(before, observed_oracle.expected_before(fixture.primary, fixture.heads, fixture.selected_ids))
            self.assertEqual(actual.retained_record.verification.semantics.mutations, fixture.plan.semantic.final_mutations)
            self.assertEqual(actual.retained_record.verification.semantics.kernel.result,
                fixture.plan.semantic.kernel_expected["result"])

    def test_unsigned_cutoff_and_real_signature_or_key_failures_cannot_reach_retained_replay(self):
        fixture = HandoffFixture(approval=False, include_audit=False)
        changed = copy.deepcopy(fixture.plan.envelope)
        changed["payload"]["revocationProofBundle"]["inputs"]["cutoffUs"] += 1
        false_signature = copy.deepcopy(fixture.plan.envelope)
        false_signature["signatureBase64Url"] = "A" * 86
        variants = ({"envelope_bytes": oracle.wire(changed)},
            {"envelope_bytes": oracle.wire(false_signature)},
            {"planner_public_key": fixture.plan.other_key.public_key()})
        for changes in variants:
            with self.subTest(changes=tuple(changes)), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(ValueError):
                    self.verify(fixture, **changes)
            self.assertEqual(replay.call_count, 0)

    def test_resigned_false_result_still_runs_genuine_proof_and_semantic_binding(self):
        fixture = HandoffFixture(approval=False, include_audit=False)
        fixture.plan.payload["expectedResult"]["revoked"] = False
        fixture.plan.rehash()
        fixture.refresh_bytes()
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.semantics, "_verify", wraps=retention.plan.semantics._verify) as semantic, \
                patch.object(retention.plan.semantics.retained, "_compute_and_package",
                    wraps=retention.plan.semantics.retained._compute_and_package) as proof:
            with self.assertRaises(ValueError):
                self.verify(fixture)
        self.assertEqual((replay.call_count, semantic.call_count, proof.call_count), (1, 1, 1))

    def test_authenticated_cutoff_views_must_agree_and_fit_exact_utc(self):
        for value in (1_000_008, -(2**63), 2**63 - 1):
            fixture = HandoffFixture(approval=False, include_audit=False)
            fixture.plan.payload["rootTransition"]["cutoffUs"] = value
            if value != 1_000_008:
                fixture.plan.payload["revocationProofBundle"]["inputs"]["cutoffUs"] = value
            fixture.plan.rehash()
            fixture.refresh_bytes()
            key = oracle._CallbackPublicKey(fixture.plan.key.public_key(), lambda: None)
            with self.subTest(cutoff=value), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(ValueError):
                    self.verify(fixture, planner_public_key=key)
            self.assertEqual((key.calls, replay.call_count), (1, 0))
        # No new positivity/currentness policy: signed microseconds are exactly
        # converted, including before epoch. This isolated arithmetic helper
        # does not authenticate these intentionally minimal component inputs.
        for cutoff in (-1, 0, 1, 999_999, 1_000_007):
            payload = {"revocationProofBundle": {"inputs": {"cutoffUs": cutoff}},
                "rootTransition": {"cutoffUs": cutoff}}
            meter = work()
            instant = handoff._authenticated_cutoff(payload, meter)
            self.assertEqual(instant, datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=cutoff))
            self.assertEqual(units(meter), oracle.canonical_comparison(cutoff, cutoff))

    def test_context_cutoff_or_coherently_resigned_cutoff_cannot_replace_original_history(self):
        for signed_change in (False, True):
            fixture = HandoffFixture(approval=False, include_audit=False)
            if signed_change:
                for value in (fixture.plan.payload["revocationProofBundle"]["inputs"], fixture.plan.payload["rootTransition"]):
                    value["cutoffUs"] += 1
                fixture.plan.rehash()
                fixture.refresh_bytes()
                changed_context = fixture.context_raw
            else:
                document = record_oracle.record_context(fixture.plan)
                document["databaseCutoffUs"] += 1
                changed_context = oracle.wire(document)
            key = oracle._CallbackPublicKey(fixture.plan.key.public_key(), lambda: None)
            with self.subTest(signed_change=signed_change), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(retention.plan, "_verify_signed_revocation_plan_on_work",
                        wraps=retention.plan._verify_signed_revocation_plan_on_work) as signed:
                with self.assertRaises(ValueError):
                    self.verify(fixture, planner_public_key=key, evaluation_context_bytes=changed_context)
            self.assertEqual((key.calls, replay.call_count, signed.call_count), (1, 1, 0))

    def test_noncanonical_original_wire_closed_shapes_and_integer_aliases_do_not_bootstrap(self):
        fixture = HandoffFixture(approval=False, include_audit=False)
        raw_variants = [b" " + fixture.raw, fixture.raw + b"\n", b'[]', b'{}', b'{',
            fixture.raw.replace(b'"schema":', b'"\\u0073chema":', 1),
            fixture.raw[:-1] + b',"schema":"' + SIGNED_SCHEMA.encode("ascii") + b'"}',
            bytearray(fixture.raw), fixture.raw.decode("ascii")]
        for value in (True, 1.0, "1", 2**63):
            changed = copy.deepcopy(fixture.plan.envelope)
            changed["payload"]["revocationProofBundle"]["inputs"]["cutoffUs"] = value
            raw_variants.append(oracle.wire(changed))
        for changed in ({**fixture.plan.envelope, "extra": None},
                {**fixture.plan.envelope, "schema": "serverware.signedPolicyAuthorityMeasuredPlan/v3"}):
            raw_variants.append(oracle.wire(changed))
        for raw in raw_variants:
            key = oracle._CallbackPublicKey(fixture.plan.key.public_key(), lambda: None)
            with self.subTest(raw_type=type(raw).__name__, length=len(raw)), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(ValueError):
                    self.verify(fixture, envelope_bytes=raw, planner_public_key=key)
            self.assertEqual((key.calls, replay.call_count), (0, 0))

    def test_all_independent_nonroot_pins_and_source_claims_are_required(self):
        fixture = HandoffFixture(approval=False, include_audit=False)
        variants = []
        for name, value in fixture.context.items():
            changed = copy.deepcopy(fixture.context)
            if type(value) is dict:
                for field in value:
                    variant = copy.deepcopy(changed)
                    variant[name][field] = oracle.sha((name + field).encode("ascii"))
                    variants.append({"context": variant})
                continue
            changed[name] = (value + 1 if type(value) is int else oracle.sha(name.encode("ascii")))
            variants.append({"context": changed})
        changed_request = copy.deepcopy(fixture.request)
        changed_request["arguments"]["reason"] = "different independent request"
        variants.extend(({"expected_request": changed_request},
            {"verifier_public_key": fixture.plan.other_key.public_key()}))
        for changes in variants:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.verify(fixture, **changes)
        for field in ("operationContractDigest", "operationManifestDigest", "handlerContractDigest", "queryManifestDigest",
                "operationId", "requestDigest"):
            changed = HandoffFixture(approval=False, include_audit=False)
            changed.plan.payload["measuredPlan"][field] = oracle.sha(field.encode("ascii"))
            changed.plan.rehash()
            changed.refresh_bytes()
            with self.subTest(source=field), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(ValueError):
                    self.verify(changed)
            self.assertEqual(replay.call_count, 0)

    def test_root_values_and_selected_inventory_never_come_from_authenticated_plan_hints(self):
        fixture = HandoffFixture(approval=False, include_audit=False)
        for attribute, field in (("business_roots", "root_digest"), ("authorization_roots", "root_digest"),
                ("counted_heads", "index_revision")):
            rows = getattr(fixture.inventory, attribute)
            value = oracle.sha(attribute.encode("ascii")) if field == "root_digest" else rows[0].index_revision + 1
            changed = replace(fixture.inventory, **{attribute: (replace(rows[0], **{field: value}), *rows[1:])})
            with self.subTest(root_class=attribute), self.assertRaises(ValueError):
                self.verify(fixture, root_inventory=changed)
        for mode in ("missing-role", "duplicate-role", "unknown-table", "missing-write-profile"):
            changed = HandoffFixture(approval=False, include_audit=False)
            queries = changed.plan.payload["revocationProofBundle"]["inputs"]["queries"]
            if mode == "missing-role":
                queries.pop()
            elif mode == "duplicate-role":
                queries[-1]["role"] = queries[0]["role"]
            elif mode == "unknown-table":
                changed.plan.payload["mutationPlan"][0]["table"] = "credentials"
            else:
                changed.plan.payload["mutationPlan"] = [mutation for mutation in changed.plan.payload["mutationPlan"]
                    if mutation["table"] != "webauthn_credentials"]
            changed.plan.rehash()
            changed.refresh_bytes()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.verify(changed)

    def test_closed_caller_carriers_reject_before_any_actual_signature(self):
        fixture = HandoffFixture(approval=False, include_audit=False)
        variants = ({"context": {**fixture.context, "expectedBefore": fixture.expected_context["expectedBefore"]}},
            {"context": {name: value for name, value in fixture.context.items() if name != "expectedFence"}},
            {"context": {**fixture.context, "authority": True}}, {"expected_request": None},
            {"root_inventory": None}, {"root_inventory": fixture.expected_context["expectedBefore"]},
            {"evaluation_context_bytes": bytearray(fixture.context_raw)})
        for changes in variants:
            key = oracle._CallbackPublicKey(fixture.plan.key.public_key(), lambda: None)
            with self.subTest(changes=tuple(changes)), self.assertRaises(ValueError):
                self.verify(fixture, planner_public_key=key, **changes)
            self.assertEqual(key.calls, 0)

    def test_original_inputs_are_owned_before_bootstrap_key_callback_and_outputs_are_detached(self):
        fixture, meter = HandoffFixture(approval=False, include_audit=False), work()
        expected = independent_work(fixture)
        context = copy.deepcopy(fixture.expected_context)
        original_raw, original_context = fixture.raw, fixture.context_raw
        def mutate_originals():
            fixture.context["expectedVerifierIdentity"].clear()
            fixture.context["maximumPlanAgeNs"] = 1
            fixture.request["arguments"]["reason"] = "changed after ownership"
            object.__setattr__(fixture.inventory.business_roots[0], "root_digest", oracle.sha(b"changed primary"))
            object.__setattr__(fixture.inventory.counted_heads[0].index_root, "digest", oracle.sha(b"changed counted"))
            fixture.raw, fixture.context_raw = b"{}", b"{}"
        key = oracle._CallbackPublicKey(fixture.plan.key.public_key(), mutate_originals)
        actual = self.verify(fixture, meter=meter, planner_public_key=key)
        self.assertEqual(key.calls, 2)
        self.assertEqual(actual.expected_context, context)
        self.assertEqual(actual.retained_record.envelope_bytes, original_raw)
        self.assertEqual(actual.retained_record.context_bytes, original_context)
        self.assertEqual(units(meter), expected["total"])
        actual.expected_context["expectedPlannerIdentity"].clear()
        actual.expected_context["expectedBefore"]["businessBeforeRoots"].clear()
        self.assertEqual(actual.retained_record.context_bytes, original_context)
        self.assertEqual(actual.retained_record.context["expectedPlannerIdentity"], context["expectedPlannerIdentity"])
        self.assertEqual(actual.retained_record.context["expectedBefore"], context["expectedBefore"])

    def test_real_signature_callbacks_cannot_spend_refund_retype_or_replace_shared_work(self):
        for stage in ("bootstrap", "retained-planner", "assertion"):
            for mode in ("spend", "refund", "float", "replace"):
                fixture, meter = HandoffFixture(approval=False, include_audit=False), work()
                meter.charge(hashes=1, input_bytes=17, json_nodes=11)
                original_limits = meter.limits
                poison = []
                planner_calls = 0
                def corrupt():
                    if mode == "spend": meter.charge(input_bytes=1)
                    elif mode == "refund": meter.hash_work -= 1
                    elif mode == "float": meter.input_bytes = float(meter.input_bytes)
                    else: meter.limits = accounting.QueryReadValidationLimits()
                    poison.append((units(meter), meter.limits))
                def planner_callback():
                    nonlocal planner_calls
                    planner_calls += 1
                    if (stage == "bootstrap" and planner_calls == 1
                            or stage == "retained-planner" and planner_calls == 2):
                        corrupt()
                planner_key = oracle._CallbackPublicKey(fixture.plan.key.public_key(), planner_callback)
                verifier_key = oracle._CallbackPublicKey(fixture.plan.semantic.receipt.key.public_key(),
                    corrupt if stage == "assertion" else lambda: None)
                with self.subTest(stage=stage, mode=mode), self.assertRaises(ValueError):
                    self.verify(fixture, meter=meter, planner_public_key=planner_key, verifier_public_key=verifier_key)
                self.assertEqual(len(poison), 1)
                self.assertEqual(units(meter), poison[0][0])
                if mode == "float": self.assertIs(type(meter.input_bytes), float)
                if stage == "bootstrap":
                    self.assertIs(meter.limits, poison[0][1])
                    if mode == "replace": self.assertIsNot(meter.limits, original_limits)
                    else: self.assertIs(meter.limits, original_limits)
                else:
                    # Real retained attachment unwind restores the entering
                    # reference, including after replacement. It never repairs
                    # poisoned counters or refunds their consumed work.
                    self.assertIs(meter.limits, original_limits)
                self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))
                self.assertEqual(planner_key.calls, 1 if stage == "bootstrap" else 2)
                self.assertEqual(verifier_key.calls, int(stage == "assertion"))

    def test_independent_exact_preconsumed_and_each_minus_one_admission_never_resets_work(self):
        fixture = HandoffFixture(approval=False, include_audit=False)
        expected = independent_work(fixture)
        for prior in ((0, 0, 0), (3, 17, 11)):
            full = oracle.add(prior, expected["admission"])
            for deficit in (None, 0, 1, 2):
                maximum = tuple(value - int(index == deficit) for index, value in enumerate(full))
                meter = work(maximum)
                meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                limits = meter.limits
                actual_initialize = accounting._ValidationWork.__init__
                mixed = retention.plan.semantics.retained.mixed
                actual_mixed = mixed._verify
                clamps, children = [], []
                def initialize(instance, child_limits):
                    # The genuine mixed worker intentionally has one child
                    # clamped to the outer ledger's remaining compact hold.
                    # Observe and delegate it; never replace the proof body.
                    self.assertEqual(len(clamps), 1)
                    self.assertEqual(children, [])
                    self.assertEqual((child_limits.max_hashes, child_limits.max_input_bytes,
                        child_limits.max_json_nodes), clamps[0])
                    self.assertIsNot(instance, meter)
                    actual_initialize(instance, child_limits)
                    children.append(instance)
                def verify_mixed(owned, ledger, raw_decode_bytes, capture):
                    self.assertIs(ledger.work, meter)
                    clamps.append(ledger.remaining())
                    return actual_mixed(owned, ledger, raw_decode_bytes, capture)
                with self.subTest(prior=prior, deficit=deficit), \
                        patch.object(accounting._ValidationWork, "__init__", new=initialize), \
                        patch.object(mixed, "_verify", new=verify_mixed):
                    if deficit is None:
                        actual = self.verify(fixture, meter=meter)
                        self.assertEqual(actual.expected_context, fixture.expected_context)
                        self.assertEqual(units(meter), oracle.add(prior, expected["total"]))
                        self.assertEqual((len(clamps), len(children)), (1, 1))
                        for name in PHASES:
                            self.assertEqual(oracle.units(getattr(actual.metrics, name)), expected[name], name)
                    else:
                        with self.assertRaises(ValueError):
                            self.verify(fixture, meter=meter)
                        self.assertTrue(all(start <= used <= ceiling
                            for start, used, ceiling in zip(prior, units(meter), maximum)))
                        self.assertLessEqual(len(children), 1)
                self.assertIs(meter.limits, limits)
                self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))

    def test_repeated_handoffs_repeat_both_signatures_and_proof_on_remaining_allowance(self):
        fixture = HandoffFixture(approval=False, include_audit=False)
        expected = independent_work(fixture)
        twice = oracle.add(expected["total"], expected["admission"])
        for deficit in (None, 0, 1, 2):
            maximum = tuple(value - int(index == deficit) for index, value in enumerate(twice))
            meter = work(maximum)
            limits = meter.limits
            planner_key = oracle._CallbackPublicKey(fixture.plan.key.public_key(), lambda: None)
            verifier_key = oracle._CallbackPublicKey(fixture.plan.semantic.receipt.key.public_key(), lambda: None)
            with self.subTest(deficit=deficit), \
                    patch.object(retention.plan.semantics, "_verify", wraps=retention.plan.semantics._verify) as semantic:
                first = self.verify(fixture, meter=meter, planner_public_key=planner_key, verifier_public_key=verifier_key)
                self.assertEqual(units(meter), expected["total"])
                if deficit is None:
                    second = self.verify(fixture, meter=meter, planner_public_key=planner_key, verifier_public_key=verifier_key)
                    self.assertEqual(second.retained_record.record_digest, first.retained_record.record_digest)
                    self.assertEqual(units(meter), oracle.add(expected["total"], expected["total"]))
                    self.assertEqual((planner_key.calls, verifier_key.calls, semantic.call_count), (4, 2, 2))
                else:
                    with self.assertRaises(ValueError):
                        self.verify(fixture, meter=meter, planner_public_key=planner_key, verifier_public_key=verifier_key)
                    self.assertTrue(all(left <= used <= ceiling
                        for left, used, ceiling in zip(expected["total"], units(meter), maximum)))
            self.assertIs(meter.limits, limits)
            self.assertFalse(hasattr(meter, "_revocation_packaging_owner"))


if __name__ == "__main__":
    unittest.main()
