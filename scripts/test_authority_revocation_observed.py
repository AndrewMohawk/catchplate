#!/usr/bin/env python3
"""Full independent root ownership/comparison and exact context projection.

Positive root observations come from the genuine .52 two-read worker against
its explicitly synthetic SQL responder. This is not database admission or a
current-root capability. The actual inert projection helpers run without an
active planner, registry replacement, proof-success callback or signer stub.
Literal expected vectors and work recipes are independent of helper results.
"""
from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_revocation_observed as observed
from catchplate import authority_revocation_roots as roots
from catchplate import authority_query_read_work as accounting
from catchplate import authority_query_reads as bookkeeping
import test_authority_revocation_roots as root_oracle
import test_authority_index_heads as head_oracle


BUSINESS = ("approval_grants", "control_plane_approvals", "metadata_audit_outbox",
    "oidc_browser_sessions", "policy_authority_bounded_aggregate_states",
    "webauthn_challenges", "webauthn_credentials")
AUTHORIZATION = ("webauthn_trust_publication_high_water", "webauthn_trust_publications")
HEADS = ("webauthn_control_approval_approved", "webauthn_credential_id",
    "webauthn_credential_live_trust", "webauthn_credential_user_history",
    "webauthn_grant_approver_active", "webauthn_publication_status",
    "webauthn_registration_unused_global", "webauthn_registration_unused_user",
    "webauthn_session_credential_status")
READ_IDS = ("webauthn_control_approval_approved", "webauthn_grant_approver_active",
    "webauthn_publication_status", "webauthn_registration_unused_global", "webauthn_session_credential_status")
ROLES = ("sessions_pending_webauthn", "sessions_active", "grants", "approvals",
    "global_registration_challenges", "pending_trust_publications")
CREDENTIAL_IDS = ("webauthn_credential_id", "webauthn_credential_live_trust", "webauthn_credential_user_history")
SELECTED_IDS = tuple(sorted(READ_IDS + CREDENTIAL_IDS))


def digest(label):
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def nodes(value):
    if type(value) is dict:
        return 1 + sum(1 + nodes(child) for child in value.values())
    if type(value) in (list, tuple):
        return 1 + sum(nodes(child) for child in value)
    return 1


def cost(value, byte_passes=2, node_passes=2):
    return 0, byte_passes * len(wire(value)), node_passes * nodes(value)


def add(*values):
    return tuple(sum(value[index] for value in values) for index in range(3))


def copy_cost(value):
    """Independent real bookkeeping-copy profile, not uniform JSON capture.

    Exact strings have one scalar walk; other scalars actually call work.wire
    before the copy's scalar charge. Every container pays an extra separator
    per element (and an extra colon per dictionary member), even when empty.
    """
    if type(value) is str:
        return 0, len(wire(value)), 1
    if type(value) is dict:
        return add((0, 2 + 2 * len(value), 1),
            *(copy_cost(item) for pair in value.items() for item in pair))
    if type(value) in (list, tuple):
        return add((0, 2 + len(value), 1), *(copy_cost(item) for item in value))
    if value is None or type(value) in (bool, int):
        return 0, 3 * len(wire(value)), 3
    raise AssertionError("fixture copy oracle is only for exact JSON")


def context():
    return {
        "expectedPlannerIdentity": {"sessionIdentityDigest": digest("planner session"),
            "measurementDigest": digest("planner measurement"), "attestationReceiptDigest": digest("planner attestation")},
        "expectedVerifierIdentity": {"sessionIdentityDigest": digest("verifier session"),
            "measurementDigest": digest("verifier measurement"), "attestationReceiptDigest": digest("verifier attestation")},
        "expectedCapabilityId": digest("capability"), "expectedPlannerTransactionId": digest("transaction"),
        "expectedFence": 7, "reservedAtEpochNs": 999_000_000_000,
        "deadlineEpochNs": 1_020_000_000_000, "deadlineMonotonicNs": 30_000_000_000,
        "nowEpochNs": 1_000_000_000_000, "nowMonotonicNs": 10_000_000_000,
        "maximumAssertionAgeNs": 30_000_000_000, "maximumPlanAgeNs": 30_000_000_000,
        "maximumClockSkewNs": 5_000_000_000, "expectedApproverPolicyDigest": None,
    }


def expected_before(primary_values, head_values, identities=HEADS):
    def primary_vector(tables):
        return [{"table": row["table_name"], "rootRevision": row["root_revision"],
            "rootDigest": row["root_digest"], "leafCount": row["leaf_count"]}
            for row in primary_values if row["table_name"] in tables]
    return {"businessBeforeRoots": primary_vector(BUSINESS),
        "authorizationBeforeRoots": primary_vector(AUTHORIZATION),
        "indexBeforeHeads": [{"indexId": row["index_id"], "indexRevision": row["index_revision"],
            "rootDigest": row["root_digest"], "leafCount": row["leaf_count"]}
            for row in head_values if row["index_id"] in identities]}


def capture_graph(primary_values, head_values):
    return {
        "businessRoots": [copy.deepcopy(row) for row in primary_values if row["table_name"] in BUSINESS],
        "authorizationRoots": [copy.deepcopy(row) for row in primary_values if row["table_name"] in AUTHORIZATION],
        "countedHeads": copy.deepcopy(head_values),
    }


def expected_context(primary_values, head_values, identities=SELECTED_IDS, original=None):
    return {**copy.deepcopy(context() if original is None else original),
        "expectedBefore": expected_before(primary_values, head_values, identities)}


def independent_work(primary_values, head_values, identities=SELECTED_IDS, original=None):
    capture = copy_cost(capture_graph(primary_values, head_values))
    full = expected_before(primary_values, head_values)
    comparison = cost(full, 6, 4)  # two genuine encoders2L2N + their byte scans1L
    projection = add(comparison, copy_cost(expected_context(primary_values, head_values, identities, original)))
    return {"capture": capture, "comparison": comparison, "projection": projection,
        "total": add(capture, projection)}


def genuine_inventory(*, populated=False, meter=None):
    primary_values = root_oracle.primary_rows(populated=populated)
    head_values = head_oracle.source_rows(populated=populated)
    acquisition = root_oracle.inventory_fixture(primary_values=primary_values,
        head_values=head_values, meter=meter)
    inventory = root_oracle.acquire(acquisition)
    return inventory, primary_values, head_values, acquisition


def work(limits=None):
    return accounting._ValidationWork(accounting.QueryReadValidationLimits(*(limits or ())))


def metrics(meter):
    return meter.hash_work, meter.input_bytes, meter.json_nodes


class RevocationObservedTests(unittest.TestCase):
    def project(self, inventory, primary_values, head_values, *, meter=None, supplied_context=None, **changes):
        return observed._project_expected_context(context() if supplied_context is None else supplied_context,
            inventory, **{"acquired_before": expected_before(primary_values, head_values),
                "query_roles": ROLES, "mutated_tables": ("webauthn_credentials",),
                "write_index_ids": CREDENTIAL_IDS, "work": work() if meter is None else meter, **changes})

    def test_partial_context_is_closed_fourteen_and_never_samples_current_time(self):
        value, meter = context(), work()
        observed._validate_partial_context(value, meter)
        self.assertEqual(metrics(meter), (0, 0, 0))
        self.assertEqual(len(value), 14)
        class ForeignString(str):
            pass
        changes = [{**value, "expectedBefore": {}}, {**value, "extra": None},
            {key: child for key, child in value.items() if key != "expectedCapabilityId"},
            {ForeignString(key) if key == "expectedFence" else key: child for key, child in value.items()},
            {**value, "expectedFence": True}, {**value, "expectedFence": 1.0},
            {**value, "nowEpochNs": value["deadlineEpochNs"]},
            {**value, "expectedCapabilityId": "sha256:" + "A" * 64},
            {**value, "expectedVerifierIdentity": {**value["expectedVerifierIdentity"], "extra": digest("extra")}}]
        for changed in changes:
            with self.subTest(context=changed), self.assertRaises(ValueError):
                observed._validate_partial_context(changed, work())
        for meter in (None, object()):
            with self.assertRaises(ValueError):
                observed._validate_partial_context(value, meter)

    def test_actual_reader_observations_are_owned_full_seven_two_nine_before_projection(self):
        for populated in (False, True):
            inventory, primary_values, head_values, acquisition = genuine_inventory(populated=populated)
            meter = work()
            captured = observed._capture_root_inventory(inventory, work=meter)
            self.assertEqual(captured, inventory)
            self.assertIsNot(captured, inventory)
            for copied, original in zip(captured.business_roots + captured.authorization_roots,
                                        inventory.business_roots + inventory.authorization_roots):
                self.assertIsNot(copied, original)
            for copied, original in zip(captured.counted_heads, inventory.counted_heads):
                self.assertIsNot(copied, original)
                self.assertIsNot(copied.index_root, original.index_root)
            self.assertEqual(observed._inventory_before(captured), expected_before(primary_values, head_values))
            self.assertEqual(metrics(meter), independent_work(primary_values, head_values)["capture"])
            self.assertEqual((len(acquisition[0].calls), acquisition[4].returned_rows), (2, 18))

    def test_exact_read_five_credential_eight_and_full_nine_subsets_come_from_independent_values(self):
        inventory, primary_values, head_values, _ = genuine_inventory(populated=True)
        variants = (
            (("metadata_audit_outbox",), (), READ_IDS),
            (("webauthn_credentials",), CREDENTIAL_IDS, SELECTED_IDS),
            (("webauthn_challenges", "webauthn_credentials"), tuple(sorted(CREDENTIAL_IDS + (
                "webauthn_registration_unused_global", "webauthn_registration_unused_user"))), HEADS),
        )
        for tables, writes, identities in variants:
            meter = work()
            captured = observed._capture_root_inventory(inventory, work=meter)
            actual_compare = observed.plan.semantics._canonical_equal
            with self.subTest(count=len(identities)), \
                    patch.object(observed.plan.semantics, "_canonical_equal", wraps=actual_compare) as comparison:
                result = self.project(captured, primary_values, head_values, meter=meter,
                    query_roles=tuple(reversed(ROLES)), mutated_tables=tables, write_index_ids=writes)
            self.assertEqual(result, expected_context(primary_values, head_values, identities))
            self.assertEqual(len(result), 15)
            self.assertEqual(comparison.call_count, 1)
            self.assertEqual(comparison.call_args.args, (expected_before(primary_values, head_values),) * 2)
            self.assertIs(comparison.call_args.kwargs["work"], meter)
            self.assertEqual(metrics(meter), independent_work(primary_values, head_values, identities)["total"])
            self.assertEqual(tuple(row["indexId"] for row in result["expectedBefore"]["indexBeforeHeads"]), identities)

    def test_unused_head_drift_is_rejected_by_full_comparison_before_subset_or_final_copy(self):
        inventory, primary_values, head_values, _ = genuine_inventory(populated=True)
        meter = work()
        captured = observed._capture_root_inventory(inventory, work=meter)
        expected = independent_work(primary_values, head_values)
        unused = "webauthn_registration_unused_user"
        self.assertNotIn(unused, SELECTED_IDS)
        acquired = expected_before(primary_values, head_values)
        next(row for row in acquired["indexBeforeHeads"] if row["indexId"] == unused)["indexRevision"] += 1
        real_copy = bookkeeping._CopyBudget.copy
        copies = []
        def copied(copier, value, *args, **kwargs):
            copies.append(value)
            return real_copy(copier, value, *args, **kwargs)
        with patch.object(bookkeeping._CopyBudget, "copy", copied):
            with self.assertRaisesRegex(ValueError, "full acquired roots differ"):
                self.project(captured, primary_values, head_values, meter=meter, acquired_before=acquired)
        self.assertEqual(copies, [])
        self.assertEqual(metrics(meter), add(expected["capture"], cost(acquired, 3, 2),
            cost(expected_before(primary_values, head_values), 3, 2)))

    def test_original_inventory_context_and_acquired_graph_mutation_cannot_retarget_owned_handoff(self):
        inventory, primary_values, head_values, acquisition = genuine_inventory(populated=True)
        original, meter = context(), work()
        independent_original = copy.deepcopy(original)
        # These are the actual ownership operations used by the caller before
        # later SQL/key callbacks, not an ownership claim inferred from a DTO.
        owned_context = bookkeeping._CopyBudget(meter).copy(original)
        captured = observed._capture_root_inventory(inventory, work=meter)
        original["expectedPlannerIdentity"].clear()
        original["expectedCapabilityId"] = digest("retargeted capability")
        object.__setattr__(inventory.business_roots[0], "root_digest", digest("retargeted primary"))
        object.__setattr__(inventory.counted_heads[-1].index_root, "digest", digest("retargeted head"))
        acquisition[0].primary.clear()
        acquisition[0].heads.clear()
        acquired = expected_before(primary_values, head_values)
        result = self.project(captured, primary_values, head_values, meter=meter,
            supplied_context=owned_context, acquired_before=acquired)
        self.assertEqual(result, expected_context(primary_values, head_values, original=independent_original))
        owned_context["expectedVerifierIdentity"].clear()
        acquired["businessBeforeRoots"].clear()
        object.__setattr__(captured.counted_heads[0].index_root, "count", 123)
        self.assertEqual(result, expected_context(primary_values, head_values, original=independent_original))
        self.assertEqual(metrics(meter), add(copy_cost(independent_original),
            independent_work(primary_values, head_values, original=independent_original)["total"]))

    def test_full_acquired_shape_order_cardinality_and_bool_integer_aliases_deny(self):
        inventory, primary_values, head_values, _ = genuine_inventory(populated=True)
        full = expected_before(primary_values, head_values)
        variants = [None, {}, {**full, "extra": []}]
        for name in ("businessBeforeRoots", "authorizationBeforeRoots", "indexBeforeHeads"):
            for changed in (full[name][:-1], full[name] + [full[name][0]], list(reversed(full[name])), tuple(full[name])):
                variants.append({**copy.deepcopy(full), name: copy.deepcopy(changed)})
        for name, field in (("businessBeforeRoots", "rootRevision"), ("authorizationBeforeRoots", "leafCount"),
                            ("indexBeforeHeads", "indexRevision")):
            for value in (True, 1.0, -1, 2**63):
                changed = copy.deepcopy(full)
                changed[name][0][field] = value
                variants.append(changed)
        for changed in variants:
            with self.subTest(before=changed), self.assertRaises(ValueError):
                self.project(inventory, primary_values, head_values, acquired_before=changed)

    def test_inventory_carriers_full_source_order_scalar_and_manifest_shapes_deny(self):
        inventory, primary_values, head_values, _ = genuine_inventory()
        variants = [None, {}, observed._inventory_before(inventory)]
        for name in ("business_roots", "authorization_roots", "counted_heads"):
            rows = getattr(inventory, name)
            variants.extend(replace(inventory, **{name: value}) for value in
                (list(rows), rows[:-1], rows + (rows[0],), tuple(reversed(rows))))
        class ForeignString(str):
            pass
        for changes in ({"table_name": "credentials"}, {"table_name": ForeignString(BUSINESS[0])},
                {"tree_depth": True}, {"tree_radix": 15}, {"root_revision": True},
                {"leaf_count": -1}, {"updated_at_epoch_ns": 2**63}, {"root_digest": "sha256:" + "A" * 64},
                {"manifest_digest": digest("not the global query manifest")}):
            variants.append(replace(inventory, business_roots=(replace(inventory.business_roots[0], **changes),
                *inventory.business_roots[1:])))
        variants.append(replace(inventory, authorization_roots=(replace(inventory.authorization_roots[0],
            manifest_digest=digest("authorization manifest is not the global query manifest")), *inventory.authorization_roots[1:])))
        for changes in ({"index_id": "webauthn_publication_generation"}, {"table": "credentials"},
                {"counted_profile": "wrong"}, {"projection_digest": "sha256:" + "Z" * 64},
                {"projection_manifest_digest": "bad"}, {"index_revision": True}):
            variants.append(replace(inventory, counted_heads=(replace(inventory.counted_heads[0], **changes),
                *inventory.counted_heads[1:])))
        for field, value in (("count", True), ("count", 1.0), ("digest", "bad")):
            forged = copy.deepcopy(inventory)
            object.__setattr__(forged.counted_heads[0].index_root, field, value)
            variants.append(forged)
        for variant in variants:
            meter = work()
            with self.subTest(inventory=variant), self.assertRaises(ValueError):
                observed._capture_root_inventory(variant, work=meter)
            self.assertEqual(metrics(meter), (0, 0, 0))

    def test_selector_metadata_cannot_supply_missing_roles_or_partial_write_profiles(self):
        inventory, primary_values, head_values, _ = genuine_inventory()
        changes = [
            {"query_roles": ROLES[:-1]}, {"query_roles": (ROLES[0],) * 6}, {"query_roles": list(ROLES)},
            {"query_roles": (*ROLES[:-1], "unknown")}, {"query_roles": (*ROLES[:-1], True)},
            {"mutated_tables": ("credentials",)}, {"mutated_tables": ["webauthn_credentials"]},
            {"mutated_tables": ("x" * 129,)}, {"write_index_ids": CREDENTIAL_IDS[:-1]},
            {"write_index_ids": tuple(reversed(CREDENTIAL_IDS))}, {"write_index_ids": CREDENTIAL_IDS + (CREDENTIAL_IDS[0],)},
            {"write_index_ids": list(CREDENTIAL_IDS)}, {"write_index_ids": ("webauthn_publication_generation",)},
        ]
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.project(inventory, primary_values, head_values, **changed)
        # Multiple actual mutations can affect the same table. Their profile
        # union remains exact; this helper does not invent a uniqueness rule.
        result = self.project(inventory, primary_values, head_values,
            mutated_tables=("webauthn_credentials", "webauthn_credentials"))
        self.assertEqual(result, expected_context(primary_values, head_values))

    def test_capture_and_projection_exact_preconsumed_and_each_byte_node_deficit(self):
        inventory, primary_values, head_values, _ = genuine_inventory(populated=True)
        expected = independent_work(primary_values, head_values)
        for phase in ("capture", "projection", "total"):
            for prior in ((0, 0, 0), (1, 17, 11)):
                # Both helpers are hash-free. A fully spent one-hash allowance
                # still succeeds; meaningful H-1 coverage includes real .52 reads.
                needed = expected[phase]
                limits = (max(1, prior[0]), prior[1] + needed[1], prior[2] + needed[2])
                for deficit in (None, 1, 2):
                    maximum = tuple(value - (index == deficit) for index, value in enumerate(limits))
                    meter = work(maximum)
                    meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                    limit_reference = meter.limits
                    def run():
                        owned = observed._capture_root_inventory(inventory, work=meter) if phase != "projection" else inventory
                        if phase != "capture":
                            return self.project(owned, primary_values, head_values, meter=meter)
                        return owned
                    with self.subTest(phase=phase, prior=prior, deficit=deficit):
                        if deficit is None:
                            result = run()
                            self.assertEqual(metrics(meter), add(prior, needed))
                            if phase != "capture": self.assertEqual(result, expected_context(primary_values, head_values))
                        else:
                            with self.assertRaises(accounting.QueryReadWorkError):
                                run()
                            self.assertTrue(all(value <= ceiling for value, ceiling in zip(metrics(meter), maximum)))
                        self.assertIs(meter.limits, limit_reference)

    def test_genuine_reader_capture_and_projection_share_exact_prior_and_all_three_deficits(self):
        primary_values, head_values = root_oracle.primary_rows(), head_oracle.source_rows()
        read = root_oracle.independent_work(primary_values, head_values)["total"]
        projected = independent_work(primary_values, head_values)["total"]
        total = add(read, projected)
        self.assertEqual((read[0], projected[0], total[0]), (84, 0, 84))
        for prior in ((0, 0, 0), (3, 17, 11)):
            full = add(prior, total)
            for deficit in (None, 0, 1, 2):
                maximum = tuple(value - (index == deficit) for index, value in enumerate(full))
                meter = work(maximum)
                meter.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                def run():
                    inventory, actual_primary, actual_heads, acquisition = genuine_inventory(meter=meter)
                    self.assertEqual((len(acquisition[0].calls), acquisition[4].returned_rows), (2, 18))
                    owned = observed._capture_root_inventory(inventory, work=meter)
                    return self.project(owned, actual_primary, actual_heads, meter=meter)
                with self.subTest(prior=prior, deficit=deficit):
                    if deficit is None:
                        self.assertEqual(run(), expected_context(primary_values, head_values))
                        self.assertEqual(metrics(meter), full)
                    else:
                        with self.assertRaises(accounting.QueryReadWorkError):
                            run()
                        self.assertTrue(all(value <= ceiling for value, ceiling in zip(metrics(meter), maximum)))

    def test_repeated_projection_and_failed_full_compare_keep_consumed_remaining_allowance(self):
        inventory, primary_values, head_values, _ = genuine_inventory()
        expected = independent_work(primary_values, head_values)
        for deficit in (False, True):
            maximum = (1, 2 * expected["total"][1] - deficit, 2 * expected["total"][2])
            meter = work(maximum)
            for iteration in (0, 1):
                if iteration == 1 and deficit:
                    with self.assertRaises(accounting.QueryReadWorkError):
                        owned = observed._capture_root_inventory(inventory, work=meter)
                        self.project(owned, primary_values, head_values, meter=meter)
                else:
                    owned = observed._capture_root_inventory(inventory, work=meter)
                    self.assertEqual(self.project(owned, primary_values, head_values, meter=meter),
                        expected_context(primary_values, head_values))
                    self.assertEqual(metrics(meter), tuple((iteration + 1) * value for value in expected["total"]))
            self.assertEqual(meter.hash_work, 0)
        meter = work()
        owned = observed._capture_root_inventory(inventory, work=meter)
        changed = expected_before(primary_values, head_values)
        changed["indexBeforeHeads"][-1]["indexRevision"] += 1
        with self.assertRaisesRegex(ValueError, "full acquired roots differ"):
            self.project(owned, primary_values, head_values, meter=meter, acquired_before=changed)
        spent = metrics(meter)
        self.assertGreater(spent[1], expected["capture"][1])
        # A private data helper has no success-token/retry state; a later call
        # pays its complete work again and cannot recover the failed work.
        self.project(owned, primary_values, head_values, meter=meter)
        self.assertEqual(metrics(meter), add(spent, expected["projection"]))

    def test_invalid_shared_work_and_foreign_carriers_fail_without_new_allowance(self):
        inventory, primary_values, head_values, _ = genuine_inventory()
        class ForeignInventory(roots._RootInventory):
            pass
        foreign = ForeignInventory(inventory.business_roots, inventory.authorization_roots, inventory.counted_heads)
        with self.assertRaises(observed.ObservedRevocationError):
            observed._capture_root_inventory(foreign, work=work())
        for supplied in (None, object()):
            with self.assertRaises(ValueError):
                observed._capture_root_inventory(inventory, work=supplied)
            with self.assertRaises(ValueError):
                observed._project_expected_context(context(), inventory, acquired_before=expected_before(primary_values, head_values),
                    query_roles=ROLES, mutated_tables=("webauthn_credentials",), write_index_ids=CREDENTIAL_IDS, work=supplied)
        for field, value in (("hash_work", True), ("input_bytes", 0.0), ("json_nodes", -1)):
            meter = work()
            setattr(meter, field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                observed._capture_root_inventory(inventory, work=meter)
            self.assertEqual(getattr(meter, field), value)


if __name__ == "__main__":
    unittest.main()
