#!/usr/bin/env python3
"""Sparse counted mutation against independent full-tree component oracles.

These tests call the real evaluator and counted hashes. The independent full
trees supply expected before/after roots and occupancy-derived work counts.
Literal keys are structural, not projection, primary membership, maintained
storage, checkpoint currentness, SQL installation or operation authority.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
import hashlib
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_index_contract as contract
from catchplate import authority_index_mutation as mutation
import test_authority_index_range as oracle


WIDTH = 160
DIGITS = "0123456789abcdef"
INPUT_DOMAIN = "catchplate.policyAuthorityIndexMutationInput/v1"


def key(prefix):
    return prefix.ljust(WIDTH, "0")


def image(prefix, *, version="old"):
    path = key(prefix)
    return contract.IndexLeaf(path, oracle.digest("key:" + path), oracle.digest("row:" + path + ":" + version))


def change(before=None, after=None):
    return mutation.IndexLeafChange((before if before is not None else after).key, before, after)


def opened_paths(changes):
    return {""} | {item.key[:depth] for item in changes for depth in range(WIDTH)}


def proof_frontier(tree, changes):
    """Walk the independent full tree, stopping at untouched boundary nodes."""
    opened = opened_paths(changes)
    targets = {item.key for item in changes}
    result = []

    def walk(prefix):
        if prefix in targets:
            if prefix in tree.leaves:
                result.append(tree.leaves[prefix])
        elif prefix not in opened:
            if prefix in tree.nodes and tree.nodes[prefix][1]:
                result.append(tree.opaque(prefix))
        else:
            for digit in DIGITS:
                walk(prefix + digit)

    walk("")
    return tuple(result)


def after_tree(before, changes):
    leaves = dict(before.leaves)
    for item in changes:
        if item.after is None:
            leaves.pop(item.key)
        else:
            leaves[item.key] = item.after
    return oracle.IndependentIndex(list(leaves.values()), before.profile)


def metrics_oracle(before, after, changes, frontier):
    opened = opened_paths(changes)

    def work(tree, which):
        total = sum(getattr(item, which) is not None for item in changes)
        for prefix in opened:
            occupied = sum(tree.nodes.get(prefix + digit, (None, 0))[1] > 0 for digit in DIGITS)
            total += 1 if occupied == 0 else 17 - occupied
        return total

    framed = [INPUT_DOMAIN, "catchplate.policyAuthorityCountedIndex/v1",
              before.profile.index_id, before.profile.table, before.profile.projection_digest,
              "160", before.root.digest, str(before.root.count), str(len(changes)), str(len(frontier))]
    for item in changes:
        framed.extend(("change", item.key))
        for name in ("before", "after"):
            value = getattr(item, name)
            framed.extend((name + "-absent",) if value is None else
                          (name + "-leaf", value.key, value.primary_key_digest, value.primary_row_digest))
    for item in frontier:
        if type(item) is contract.IndexLeaf:
            framed.extend(("leaf", item.key, item.primary_key_digest, item.primary_row_digest))
        else:
            framed.extend(("opaque", item.prefix, item.digest, str(item.count)))
    return {"changes": len(changes), "frontier_entries": len(frontier), "opened_nodes": len(opened),
            "child_slots": 32 * len(opened), "before_hashes": work(before, "before"),
            "after_hashes": work(after, "after"), "input_bytes": sum(8 + len(value.encode("ascii")) for value in framed)}


def field_values(value):
    return {field.name: getattr(value, field.name) for field in fields(value)}


def forged(value, **changes):
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(value, field.name)))
    return result


class IndexMutationTests(unittest.TestCase):
    def setUp(self):
        self.leaves = [image("00"), image("01"), image("7f"), image("f")]
        self.before = oracle.IndependentIndex(self.leaves)
        self.limits = mutation.IndexMutationLimits()

    def evaluate(self, before=None, changes=(), frontier=None, **options):
        before = self.before if before is None else before
        frontier = proof_frontier(before, changes) if frontier is None else frontier
        args = {"profile": before.profile, "before_root": before.root, "changes": changes,
                "frontier": frontier, "limits": self.limits}
        args.update(options)
        return mutation.evaluate_index_mutations(**args)

    def assert_transition(self, before, changes):
        frontier = proof_frontier(before, changes)
        expected_after = after_tree(before, changes)
        expected_metrics = metrics_oracle(before, expected_after, changes, frontier)
        result = self.evaluate(before, changes, frontier)
        self.assertEqual(result.before_root, before.root)
        self.assertEqual(result.after_root, expected_after.root)
        self.assertEqual(field_values(result.metrics), expected_metrics)
        self.assertEqual(result.metrics.hashes, expected_metrics["before_hashes"] + expected_metrics["after_hashes"])
        return result

    def test_insert_into_empty_tree_proves_all_absent_ancestors_and_real_after_root(self):
        empty = oracle.IndependentIndex([])
        result = self.assert_transition(empty, (change(after=image("0")),))
        self.assertEqual((result.before_root.count, result.after_root.count), (0, 1))
        self.assertEqual((result.metrics.opened_nodes, result.metrics.before_hashes,
                          result.metrics.after_hashes, result.metrics.hashes), (160, 160, 2561, 2721))

    def test_delete_only_leaf_hashes_opened_empty_paths_after_the_change(self):
        leaf = image("f")
        before = oracle.IndependentIndex([leaf])
        result = self.assert_transition(before, (change(before=leaf),))
        self.assertEqual((result.before_root.count, result.after_root.count), (1, 0))
        self.assertEqual((result.metrics.before_hashes, result.metrics.after_hashes), (2561, 160))

    def test_mixed_insert_delete_update_matches_independent_whole_tree(self):
        changes = tuple(sorted((change(before=self.leaves[0]),
            change(before=self.leaves[1], after=image("01", version="new")),
            change(after=image("80"))), key=lambda item: item.key))
        result = self.assert_transition(self.before, changes)
        self.assertEqual((result.before_root.count, result.after_root.count), (4, 4))
        self.assertNotEqual(result.before_root.digest, result.after_root.digest)

    def test_fullrow_same_key_update_and_equal_images_are_both_explicit(self):
        before = oracle.IndependentIndex([image("a")])
        original = before.leaves[key("a")]
        updated = self.assert_transition(before, (change(original, image("a", version="next")),))
        self.assertEqual(updated.before_root.count, updated.after_root.count)
        self.assertNotEqual(updated.before_root.digest, updated.after_root.digest)
        unchanged = self.assert_transition(before, (change(original, original),))
        self.assertEqual(unchanged.before_root, unchanged.after_root)
        self.assertEqual((unchanged.metrics.before_hashes, unchanged.metrics.after_hashes), (2561, 2561))

    def test_key_moves_are_separate_sorted_delete_and_insert_targets(self):
        old = self.leaves[0]
        moved = replace(old, key=key("ab"))
        changes = (change(before=old), change(after=moved))
        result = self.assert_transition(self.before, changes)
        self.assertEqual(result.before_root.count, result.after_root.count)
        self.assertNotEqual(result.before_root.digest, result.after_root.digest)

    def test_zero_changes_reconstruct_empty_and_nonempty_roots_twice(self):
        for before in (oracle.IndependentIndex([]), self.before):
            with self.subTest(count=before.root.count):
                result = self.assert_transition(before, ())
                self.assertEqual(result.before_root, result.after_root)
                self.assertEqual((result.metrics.opened_nodes, result.metrics.child_slots), (1, 32))
                self.assertTrue(all(type(item) is contract.OpaqueSubtree and len(item.prefix) == 1
                                    for item in proof_frontier(before, ())))
                with self.assertRaisesRegex(mutation.IndexMutationError, "reconstructed before root"):
                    self.evaluate(before, before_root=replace(before.root, digest="sha256:" + "0" * 64))

    def test_deep_shared_and_separate_prefixes_match_full_tree_at_leaf_siblings(self):
        keys = ("a" * 159 + "0", "a" * 159 + "1", "a" * 158 + "b0", "f" * 160)
        before = oracle.IndependentIndex([image(value) for value in keys])
        changes = (change(before=before.leaves[keys[0]], after=image(keys[0], version="new")),
                   change(after=image("a" * 159 + "2")))
        self.assert_transition(before, changes)
        proof = proof_frontier(before, changes)
        self.assertTrue(any(type(item) is contract.OpaqueSubtree and len(item.prefix) == 160 for item in proof))

    def test_actual_sha_calls_equal_both_phase_metrics_without_cached_discount(self):
        changes = (change(before=self.leaves[0], after=image("00", version="new")), change(after=image("80")))
        proof = proof_frontier(self.before, changes)
        expected_after = after_tree(self.before, changes)
        expected_metrics = metrics_oracle(self.before, expected_after, changes, proof)
        real_hash = hashlib.sha256
        for _ in range(2):
            with mock.patch.object(hashlib, "sha256", wraps=real_hash) as observed:
                result = self.evaluate(self.before, changes, proof)
            self.assertEqual(observed.call_count, expected_metrics["before_hashes"] + expected_metrics["after_hashes"])
            self.assertEqual(result.after_root, expected_after.root)
            self.assertEqual(field_values(result.metrics), expected_metrics)

    def test_missing_or_conflicting_before_target_leaf_is_not_hidden_as_opaque(self):
        changes = (change(before=self.leaves[0]),)
        proof = proof_frontier(self.before, changes)
        required = next(item for item in proof if type(item) is contract.IndexLeaf)
        without = tuple(item for item in proof if item is not required)
        with self.assertRaisesRegex(mutation.IndexMutationError, "omitted a required before leaf"):
            self.evaluate(changes=changes, frontier=without)
        wrong = replace(required, primary_row_digest=oracle.digest("different"))
        with self.assertRaisesRegex(mutation.IndexMutationError, "exact before image"):
            self.evaluate(changes=changes, frontier=tuple(wrong if item is required else item for item in proof))
        hidden = self.before.opaque(required.key)
        with self.assertRaisesRegex(mutation.IndexMutationError, "untouched immediate sibling"):
            self.evaluate(changes=changes, frontier=tuple(hidden if item is required else item for item in proof))

    def test_insert_requires_actual_old_nonmembership_not_absent_image_assertion(self):
        existing = self.leaves[0]
        changes = (change(after=replace(existing, primary_row_digest=oracle.digest("replacement"))),)
        genuine_frontier = proof_frontier(self.before, changes)
        with self.assertRaisesRegex(mutation.IndexMutationError, "exact before image"):
            self.evaluate(changes=changes, frontier=genuine_frontier)
        falsely_absent = tuple(item for item in genuine_frontier if type(item) is not contract.IndexLeaf)
        with self.assertRaisesRegex(mutation.IndexMutationError, "reconstructed before root"):
            self.evaluate(changes=changes, frontier=falsely_absent)

    def test_missing_or_corrupt_untouched_sibling_changes_the_reconstructed_root(self):
        changes = (change(before=self.leaves[0]),)
        proof = proof_frontier(self.before, changes)
        opaque = next(item for item in proof if type(item) is contract.OpaqueSubtree)
        for altered in (None, replace(opaque, digest=oracle.digest("false opaque")),
                        replace(opaque, count=opaque.count + 1)):
            supplied = tuple(altered if item is opaque else item for item in proof
                             if item is not opaque or altered is not None)
            with self.subTest(altered=altered), \
                    self.assertRaisesRegex(mutation.IndexMutationError, "reconstructed before root"):
                self.evaluate(changes=changes, frontier=supplied)

    def test_frontier_rejects_extra_leaves_hidden_open_paths_and_noncanonical_covers(self):
        changes = (change(before=self.leaves[0]),)
        proof = proof_frontier(self.before, changes)
        invalid = (
            tuple(reversed(proof)), (*proof, proof[0]),
            (self.leaves[1],), (self.before.opaque("0"),),
            (self.before.opaque("7f"),),
            (forged(self.before.opaque("7"), prefix=""),),
            (object(),), list(proof),
        )
        genuine = hashlib.sha256
        for supplied in invalid:
            with self.subTest(kind=type(supplied)), mock.patch.object(hashlib, "sha256", wraps=genuine) as hashes:
                with self.assertRaises(mutation.IndexMutationError):
                    self.evaluate(changes=changes, frontier=supplied)
                self.assertEqual(hashes.call_count, 0)
        # With no targets only depth-one opaque children are admissible.
        with self.assertRaisesRegex(mutation.IndexMutationError, "untouched immediate sibling"):
            self.evaluate(frontier=(self.before.opaque("00"),))

    def test_change_inventory_is_exact_sorted_unique_and_matches_both_image_keys(self):
        old, other = self.leaves[:2]
        for arguments in ((old.key, None, None), (key("b"), old, None),
                          (old.key, old, other), (True, old, None), ("A" * 160, old, None),
                          ("0" * 159, old, None), (old.key, {}, None)):
            with self.subTest(arguments=arguments), self.assertRaises(mutation.IndexMutationError):
                mutation.IndexLeafChange(*arguments)
        a, b = change(before=old), change(before=other)
        class ChangeSubclass(mutation.IndexLeafChange):
            pass
        cases = ([a], (b, a), (a, a), (ChangeSubclass(**field_values(a)),),
                 (object.__new__(mutation.IndexLeafChange),),
                 (forged(a, after=other),), (forged(a, key="0" * 161),))
        real_hash = hashlib.sha256
        for supplied in cases:
            with self.subTest(kind=type(supplied)), mock.patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
                with self.assertRaises(mutation.IndexMutationError):
                    self.evaluate(changes=supplied, frontier=())
                self.assertEqual(hashes.call_count, 0)

    def test_typed_context_snapshots_reject_forgery_even_with_no_changes(self):
        class ProfileSubclass(contract.IndexProfile):
            pass
        class RootSubclass(contract.CountedNode):
            pass
        class LimitsSubclass(mutation.IndexMutationLimits):
            pass
        cases = [
            {"profile": None}, {"profile": object.__new__(contract.IndexProfile)},
            {"profile": ProfileSubclass(**field_values(self.before.profile))},
            {"profile": forged(self.before.profile, table="bad-table")},
            {"before_root": None}, {"before_root": object.__new__(contract.CountedNode)},
            {"before_root": RootSubclass(**field_values(self.before.root))},
            {"before_root": forged(self.before.root, count=True)},
            {"before_root": forged(self.before.root, digest="sha256:" + "g" * 64)},
            {"limits": None}, {"limits": object.__new__(mutation.IndexMutationLimits)},
            {"limits": LimitsSubclass()}, {"limits": forged(self.limits, max_hashes=False)},
        ]
        real_hash = hashlib.sha256
        for supplied in cases:
            with self.subTest(fields=tuple(supplied)), mock.patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
                with self.assertRaises(mutation.IndexMutationError):
                    self.evaluate(**supplied)
                self.assertEqual(hashes.call_count, 0)

    def test_declared_source_limits_are_positive_exact_and_cannot_be_expanded(self):
        self.assertEqual(field_values(self.limits), {"max_changes": 514, "max_frontier_entries": 1315856,
            "max_opened_nodes": 82241, "max_hashes": 2632740, "max_input_bytes": 67108864})
        for name, maximum in field_values(self.limits).items():
            self.assertEqual(getattr(replace(self.limits, **{name: 1}), name), 1)
            for value in (0, -1, True, False, 1.0, "1", maximum + 1):
                with self.subTest(name=name, value=value), self.assertRaises(mutation.IndexMutationError):
                    replace(self.limits, **{name: value})

    def test_exact_bytes_hashes_opened_and_record_limits_admit_then_deny_before_hashing(self):
        changes = (change(before=self.leaves[0]), change(after=image("80")))
        proof = proof_frontier(self.before, changes)
        baseline = self.evaluate(changes=changes, frontier=proof)
        exact = mutation.IndexMutationLimits(max_changes=len(changes), max_frontier_entries=len(proof),
            max_opened_nodes=baseline.metrics.opened_nodes, max_hashes=baseline.metrics.hashes,
            max_input_bytes=baseline.metrics.input_bytes)
        self.assertEqual(self.evaluate(changes=changes, frontier=proof, limits=exact), baseline)
        real_hash = hashlib.sha256
        for name in field_values(exact):
            lower = replace(exact, **{name: getattr(exact, name) - 1})
            with self.subTest(bound=name), mock.patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
                with self.assertRaises(mutation.IndexMutationError):
                    self.evaluate(changes=changes, frontier=proof, limits=lower)
                self.assertEqual(hashes.call_count, 0)

    def test_all_514_change_slots_work_without_expanding_the_profile(self):
        # Adjacent literal keys keep this real boundary fixture compact while
        # exercising all source slots, not a lowered fake maximum.
        empty = oracle.IndependentIndex([])
        changes = tuple(change(after=image(f"{number:0160x}")) for number in range(514))
        result = self.assert_transition(empty, changes)
        self.assertEqual((result.metrics.changes, result.after_root.count), (514, 514))
        real_hash = hashlib.sha256
        with mock.patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
            with self.assertRaisesRegex(mutation.IndexMutationError, "changes exceed"):
                self.evaluate(empty, (*changes, changes[-1]), ())
            self.assertEqual(hashes.call_count, 0)

    def test_before_and_after_count_overflow_and_leaf_slot_capacity_reject_before_hashing(self):
        maximum = 2**63 - 1
        left = contract.OpaqueSubtree("0", oracle.digest("opaque left"), maximum)
        right = contract.OpaqueSubtree("f", oracle.digest("opaque right"), 1)
        # This is an independently hashed declared opaque root, not a claim
        # that a real maintained store contains 2^63-1 enumerated records.
        before_root = contract.CountedNode(*oracle.parent(self.before.profile, "",
            [(left.digest, left.count)] + [None] * 15))
        insert = change(after=image("f" * 160))
        leaf_slot = contract.OpaqueSubtree("0" * 159 + "1", oracle.digest("one slot"), 1)
        cases = (((), (left, right), before_root), ((insert,), (left,), before_root),
                 ((change(after=image("0" * 160)),), (forged(leaf_slot, count=2),), self.before.root))
        real_hash = hashlib.sha256
        for changes, proof, root in cases:
            with self.subTest(targets=len(changes)), mock.patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
                with self.assertRaises(mutation.IndexMutationError):
                    self.evaluate(changes=changes, frontier=proof, before_root=root)
                self.assertEqual(hashes.call_count, 0)

    def test_wrong_before_anchor_stops_before_after_hash_phase(self):
        changes = (change(before=self.leaves[0], after=image("00", version="new")),)
        proof = proof_frontier(self.before, changes)
        expected = metrics_oracle(self.before, after_tree(self.before, changes), changes, proof)
        false_root = replace(self.before.root, digest="sha256:" + "0" * 64)
        real_hash = hashlib.sha256
        with mock.patch.object(hashlib, "sha256", wraps=real_hash) as hashes:
            with self.assertRaisesRegex(mutation.IndexMutationError, "reconstructed before root"):
                self.evaluate(changes=changes, frontier=proof, before_root=false_root)
            self.assertEqual(hashes.call_count, expected["before_hashes"])

    def test_owned_snapshot_survives_controlled_mutation_and_results_are_frozen(self):
        changes = (change(before=self.leaves[0], after=image("00", version="new")),)
        proof = proof_frontier(self.before, changes)
        expected = self.evaluate(changes=changes, frontier=proof)
        opaque = next(item for item in proof if type(item) is contract.OpaqueSubtree)
        changed = False
        real_hash = hashlib.sha256
        def observe(*args, **kwargs):
            nonlocal changed
            if not changed:
                changed = True
                # Deterministic caller mutation at the first actual SHA call,
                # after snapshots; not a simultaneous-thread safety claim.
                object.__setattr__(changes[0], "after", None)
                object.__setattr__(changes[0].before, "primary_row_digest", "sha256:" + "f" * 64)
                object.__setattr__(opaque, "count", 999)
                object.__setattr__(self.before.root, "count", 999)
                object.__setattr__(self.before.profile, "table", "changed")
                object.__setattr__(self.limits, "max_hashes", 1)
            return real_hash(*args, **kwargs)
        with mock.patch.object(hashlib, "sha256", side_effect=observe):
            result = self.evaluate(changes=changes, frontier=proof)
        self.assertTrue(changed)
        self.assertEqual(result, expected)
        self.assertIsNot(result.before_root, self.before.root)
        for value, name, replacement in ((result, "after_root", expected.before_root),
                                         (result.before_root, "count", 0),
                                         (result.after_root, "count", 0),
                                         (result.metrics, "before_hashes", 0)):
            with self.subTest(type=type(value)), self.assertRaises(FrozenInstanceError):
                setattr(value, name, replacement)


if __name__ == "__main__":
    unittest.main()
