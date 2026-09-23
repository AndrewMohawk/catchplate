#!/usr/bin/env python3
"""Real primary-engine owned-input tests against independent component trees.

These authored pure tests do not execute PostgreSQL, a registry or a transition
kernel, and do not prove root currentness or operation authorization. The tree,
SQL hash and wire encoders come from the independent existing primary fixture,
not the production evaluator. Observers always delegate to the actual engine.
"""
from __future__ import annotations

import copy
import dataclasses
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_radix_mutation as primary
from test_authority_radix_mutation import (
    IndependentTree, LIMITS, batch, change, refresh_proof_digest,
)
from test_authority_radix_proof import sql_digest, sql_json, wire_json


def _json_nodes(value: object) -> int:
    if type(value) is dict:
        return 1 + sum(_json_nodes(key) + _json_nodes(child) for key, child in value.items())
    if type(value) is list:
        return 1 + sum(_json_nodes(child) for child in value)
    return 1


class PrimaryMutationInputsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = [
            {"id": "updated", "value": {"nested": [1, None, "雪"]}},
            {"id": "deleted", "value": 2},
            {"id": "read-only", "value": [3]},
            {"id": "opaque-unselected", "value": 4},
        ]
        self.tree = IndependentTree(self.rows)
        selected = tuple(self.tree.selected({"id": identifier})
                         for identifier in ("updated", "inserted", "deleted", "read-only"))
        self.after = {"id": "updated", "value": {"nested": [5, None, "é"]}}
        self.inserted = {"id": "inserted", "value": {"nested": [6]}}
        mutations = (change(selected[2], "DELETE", None),
                     change(selected[1], "INSERT", self.inserted),
                     change(selected[0], "UPDATE", self.after))
        self.arguments = batch(self.tree, selected, mutations)
        # Exact business addresses, not input tuple positions, join inventories.
        self.arguments["before_proofs"] = tuple(reversed(self.arguments["before_proofs"]))
        self.expected_tree = IndependentTree(
            [self.rows[2], self.rows[3], self.after, self.inserted], revision=7,
        )

    def test_mixed_real_batch_matches_independent_roots_wire_and_exact_metrics(self) -> None:
        pristine = copy.deepcopy(self.arguments)
        old_api = primary.evaluate_primary_radix_batch(**self.arguments)
        observed = primary.evaluate_primary_radix_inputs(**self.arguments)
        self.assertIs(type(observed), primary.PrimaryRadixMutationInputs)
        self.assertEqual(observed.result, old_api)
        self.assertEqual(wire_json(observed.result.json_projection()), wire_json(old_api.json_projection()))
        self.assertEqual(observed.result.business_after_roots, (self.expected_tree.root,))
        self.assertEqual(observed.result.authorization_after_roots, ())
        self.assertEqual(observed.selected_rows, pristine["selected_rows"])
        self.assertEqual(observed.before_proofs, pristine["before_proofs"])
        self.assertEqual(observed.mutations, pristine["mutations"])
        self.assertEqual(self.arguments, pristine)

        prefixes = set()
        for mutation in pristine["mutations"]:
            path = sql_digest("serverware.policyAuthorityAuthenticatedKey/v1",
                              b"items", sql_json(mutation["key"]))[7:]
            prefixes.update(path[:depth] for depth in range(64))
        copied_input = {
            "contracts": [{"table": "items", "keyColumns": ["id"],
                           "writeAccess": True, "rootClass": "business"}],
            "businessRoots": [{"table": "items", "rootRevision": 4,
                               "rootDigest": self.tree.root.root_digest, "leafCount": 4}],
            "authorizationRoots": [], "selected": list(pristine["selected_rows"]),
            "proofs": list(pristine["before_proofs"]), "mutations": list(pristine["mutations"]),
        }
        self.assertEqual(observed.result.metrics.json_projection(), {
            "selectedRows": 4, "mutations": 3, "proofVectors": 256,
            "proofChildSlots": 4096, "recomputedAncestors": len(prefixes),
            "hashWork": 66 + 3 * 70 + 68 + 4 + len(prefixes),
            "inputBytes": len(wire_json(copied_input)), "jsonNodes": _json_nodes(copied_input),
        })

    def test_owned_old_new_keys_and_proof_vectors_are_detached_from_callers(self) -> None:
        # Deliberately share the original selected/expected-row object. The
        # actual bounded snapshot must still own both copies independently.
        self.arguments["mutations"][2]["expectedRow"] = self.arguments["selected_rows"][0]["row"]
        pristine = copy.deepcopy(self.arguments)
        observed = primary.evaluate_primary_radix_inputs(**self.arguments)
        for name in ("selected_rows", "before_proofs", "mutations"):
            for owned, caller in zip(getattr(observed, name), self.arguments[name]):
                self.assertIsNot(owned, caller)
                self.assertIsNot(owned["key"], caller["key"])
        update = observed.mutations[2]
        self.assertIsNot(update["expectedRow"], observed.selected_rows[0]["row"])
        self.assertIsNot(update["expectedRow"]["value"]["nested"],
                         self.arguments["mutations"][2]["expectedRow"]["value"]["nested"])
        self.assertIsNot(update["row"]["value"]["nested"],
                         self.arguments["mutations"][2]["row"]["value"]["nested"])
        self.assertIsNot(observed.before_proofs[0]["siblings"][0]["childDigests"],
                         self.arguments["before_proofs"][0]["siblings"][0]["childDigests"])
        self.arguments["selected_rows"][0]["row"]["value"]["nested"].append("caller-old")
        self.arguments["mutations"][2]["row"]["value"]["nested"].append("caller-new")
        self.arguments["mutations"][1]["key"]["id"] = "caller-key"
        self.arguments["before_proofs"][0]["siblings"][0]["childDigests"][0] = "sha256:" + "0" * 64
        for name in ("selected_rows", "before_proofs", "mutations"):
            self.assertEqual(getattr(observed, name), pristine[name])
        self.assertIsNone(observed.mutations[0]["row"])
        self.assertIsNone(observed.mutations[1]["expectedRow"])

    def test_same_single_snapshot_is_returned_after_real_verification_not_a_later_copy(self) -> None:
        pristine = copy.deepcopy(self.arguments)
        expected = primary.evaluate_primary_radix_batch(**pristine)
        original = primary._Budget.snapshot
        captured = []

        def snapshot(budget, value, depth=0, ancestors=frozenset()):
            owned = original(budget, value, depth, ancestors)
            if depth == 0:
                captured.append(owned)
                # Mutation after the real detached copy, before proof/CAS
                # evaluation. No verifier result or successful hash is mocked.
                self.arguments["selected_rows"][0]["row"]["value"]["nested"].append("changed")
                self.arguments["mutations"][2]["expectedRow"]["value"]["nested"].append("changed")
                self.arguments["mutations"][2]["row"]["value"]["nested"].append("changed")
                self.arguments["before_proofs"][0]["rootDigest"] = "sha256:" + "a" * 64
            return owned

        with mock.patch.object(primary._Budget, "snapshot", snapshot):
            observed = primary.evaluate_primary_radix_inputs(**self.arguments)
        self.assertEqual(len(captured), 1)
        self.assertEqual(observed.result, expected)
        for result_name, snapshot_name in (("selected_rows", "selected"),
                                           ("before_proofs", "proofs"), ("mutations", "mutations")):
            self.assertEqual(getattr(observed, result_name), pristine[result_name])
            for row, engine_row in zip(getattr(observed, result_name), captured[0][snapshot_name]):
                self.assertIs(row, engine_row)
        self.assertNotEqual(self.arguments, pristine)

    def test_invalid_selected_row_and_freshly_redigested_false_proof_are_rejected(self) -> None:
        changed = copy.deepcopy(self.arguments)
        changed["selected_rows"][0]["row"]["value"]["nested"][0] = 99
        with self.assertRaisesRegex(primary.PrimaryRadixMutationError, "before proof reconstruction"):
            primary.evaluate_primary_radix_inputs(**changed)
        changed = copy.deepcopy(self.arguments)
        changed["before_proofs"][0]["rowDigest"] = "sha256:" + "a" * 64
        refresh_proof_digest(changed["before_proofs"][0])
        with self.assertRaisesRegex(primary.PrimaryRadixMutationError, "before proof reconstruction"):
            primary.evaluate_primary_radix_inputs(**changed)

    def test_full_old_image_cas_rejects_changes_including_boolean_integer_aliases(self) -> None:
        for replacement in (True, 99):
            with self.subTest(replacement=replacement):
                changed = copy.deepcopy(self.arguments)
                changed["mutations"][2]["expectedRow"]["value"]["nested"][0] = replacement
                with self.assertRaisesRegex(primary.PrimaryRadixMutationError, "old full-row CAS"):
                    primary.evaluate_primary_radix_inputs(**changed)
        changed = copy.deepcopy(self.arguments)
        changed["mutations"][0]["expectedRow"] = None
        with self.assertRaisesRegex(primary.PrimaryRadixMutationError, "old full-row CAS"):
            primary.evaluate_primary_radix_inputs(**changed)

    def test_new_image_key_lifecycle_and_duplicate_actions_are_actually_validated(self) -> None:
        cases = (
            (2, "row", {"id": "other-key", "value": 1}, "original key changed"),
            (2, "row", None, "UPDATE requires"),
            (0, "row", {"id": "deleted"}, "DELETE requires"),
            (1, "expectedRow", {"id": "inserted"}, "INSERT lifecycle"),
        )
        for ordinal, field, value, reason in cases:
            with self.subTest(ordinal=ordinal, field=field):
                changed = copy.deepcopy(self.arguments)
                changed["mutations"][ordinal][field] = value
                with self.assertRaisesRegex(primary.PrimaryRadixMutationError, reason):
                    primary.evaluate_primary_radix_inputs(**changed)
        with self.assertRaisesRegex(primary.PrimaryRadixMutationError, "unselected or duplicated"):
            primary.evaluate_primary_radix_inputs(**{
                **self.arguments, "mutations": self.arguments["mutations"] + (self.arguments["mutations"][0],),
            })

    def test_returned_containers_are_observations_not_success_token_inputs(self) -> None:
        observed = primary.evaluate_primary_radix_inputs(**self.arguments)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            observed.mutations = ()
        constructed = primary.PrimaryRadixMutationInputs(
            observed.result, observed.selected_rows, observed.before_proofs, observed.mutations,
        )
        for token in (observed, constructed):
            for name in ("selected_rows", "before_proofs", "mutations"):
                with self.subTest(name=name, constructed=token is constructed):
                    with self.assertRaisesRegex(primary.PrimaryRadixMutationError, "inventories must be tuples"):
                        primary.evaluate_primary_radix_inputs(**{**self.arguments, name: token})
        # Inner values remain mutable, but a later call must genuinely reverify
        # them, not trust the accompanying previously successful result.
        observed.mutations[2]["expectedRow"]["value"]["nested"].append("tampered")
        with self.assertRaisesRegex(primary.PrimaryRadixMutationError, "old full-row CAS"):
            primary.evaluate_primary_radix_inputs(**{
                **self.arguments, "selected_rows": observed.selected_rows,
                "before_proofs": observed.before_proofs, "mutations": observed.mutations,
            })

    def test_empty_mutations_preserve_existing_membership_api_and_authorization_roots(self) -> None:
        auth = IndependentTree([{"id": "authority", "enabled": True}], table="authorization")
        selected_auth = auth.selected({"id": "authority"})
        arguments = {
            **self.arguments, "table_contracts": (self.tree.contract(),
                auth.contract(writable=False, root_class="authorization")),
            "authorization_before_roots": (auth.root,),
            "selected_rows": self.arguments["selected_rows"] + (selected_auth,),
            "before_proofs": (auth.proof(selected_auth),) + self.arguments["before_proofs"], "mutations": (),
        }
        observed = primary.evaluate_primary_radix_inputs(**arguments)
        memberships = primary.evaluate_primary_radix_memberships(**{
            name: value for name, value in arguments.items() if name != "mutations"
        })
        self.assertIs(type(memberships), primary.PrimaryRadixMembershipResult)
        self.assertEqual(observed.result, memberships.result)
        self.assertEqual(observed.selected_rows, memberships.selected_rows)
        self.assertEqual(observed.before_proofs, memberships.before_proofs)
        self.assertEqual(observed.mutations, ())
        self.assertEqual(observed.result.business_after_roots, (self.tree.root,))
        self.assertEqual(observed.result.authorization_after_roots, (auth.root,))
        empty = primary.evaluate_primary_radix_inputs(**{
            **arguments, "selected_rows": (), "before_proofs": (),
        })
        self.assertEqual((empty.selected_rows, empty.before_proofs, empty.mutations), ((), (), ()))
        self.assertEqual(empty.result.metrics.hash_work, 66)

    def test_real_input_budgets_still_reject_before_returning_observations(self) -> None:
        metrics = primary.evaluate_primary_radix_inputs(**self.arguments).result.metrics
        for field, value, reason in (
            ("max_hashes", metrics.hash_work - 1, "hash budget"),
            ("max_input_bytes", metrics.input_bytes - 1, "input byte budget"),
            ("max_json_nodes", metrics.json_nodes - 1, "JSON structure budget"),
            ("max_mutations", 2, "inventory count"),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(primary.PrimaryRadixMutationError, reason):
                    primary.evaluate_primary_radix_inputs(**{
                        **self.arguments, "limits": dataclasses.replace(LIMITS, **{field: value}),
                    })
        exact = dataclasses.replace(LIMITS, max_hashes=metrics.hash_work,
                                    max_input_bytes=metrics.input_bytes, max_json_nodes=metrics.json_nodes)
        self.assertEqual(primary.evaluate_primary_radix_inputs(**{
            **self.arguments, "limits": exact,
        }).result.metrics, metrics)


if __name__ == "__main__":
    unittest.main()
