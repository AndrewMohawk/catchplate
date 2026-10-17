#!/usr/bin/env python3
"""Deterministic relative-count controls using an independent hash/tree oracle.

These do not establish maintained cross-table eligibility, trusted heads or
live challenge pruning. Enumeration keeps its original opaque-subtree denial.
"""
from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_index_contract as contract
from catchplate import authority_index_range as ranges
from catchplate import authority_index_range_count as counts
from catchplate import authority_query_read_work as measured
from scripts.test_authority_index_range import (
    IndependentIndex, NIBBLES, TOP, WIDTH, bypassed, digest, key, leaf, span,
)


def count_frontier(tree, interval):
    """Independent oracle: stop only at disjoint or fully covered subtrees."""
    start = int(interval.lower, 16)
    end = TOP if interval.upper is None else int(interval.upper, 16)
    result = []

    def walk(prefix):
        node = tree.nodes.get(prefix)
        if node is None or not node[1]:
            return
        low, high = span(prefix)
        intersects = start != end and low < end and start < high
        if prefix and (not intersects or start <= low and high <= end):
            result.append(tree.opaque(prefix))
        else:
            for digit in NIBBLES:
                walk(prefix + digit)

    walk("")
    return tuple(result)


class AuthorityIndexRangeCountTests(unittest.TestCase):
    def setUp(self):
        self.tree = IndependentIndex([leaf(key(prefix))
            for prefix in ("0", "0f", "1", "11", "20", "7f", "f")])
        self.all = contract.KeyInterval(key("0"), None)

    def verify(self, *, tree=None, interval=None, frontier=None, limits=None,
               root=None, profile=None, work=None):
        tree = self.tree if tree is None else tree
        interval = self.all if interval is None else interval
        return counts._reconstruct_index_range_count(
            profile=tree.profile if profile is None else profile,
            expected_root=tree.root if root is None else root,
            interval=interval,
            frontier=count_frontier(tree, interval) if frontier is None else frontier,
            limits=ranges.IndexRangeLimits() if limits is None else limits, work=work)

    def test_counts_match_independent_enumeration_at_boundaries(self):
        for lower, upper in (("0", None), ("1", "2"), ("10", "12"),
                             ("0f", "11"), ("3", "7"), ("f", None)):
            with self.subTest(lower=lower, upper=upper):
                interval = contract.KeyInterval(key(lower), None if upper is None else key(upper))
                observed = self.verify(interval=interval)
                self.assertEqual(observed.count, len(self.tree.matches(interval)))
                self.assertEqual(observed.root, self.tree.root)
                self.assertGreaterEqual(observed.metrics.opened_nodes, 1)

    def test_population_larger_than_leaf_budget_without_cap_increase(self):
        tree = IndependentIndex([leaf(format(number, "0160x")) for number in range(300)])
        observed = self.verify(tree=tree, limits=ranges.IndexRangeLimits(max_leaves=1))
        self.assertEqual(observed.count, 300)
        self.assertEqual(observed.metrics.leaves, 0)
        self.assertEqual(observed.metrics.entries, 1)
        self.assertEqual(observed.metrics.opened_nodes, 1)

    def test_old_enumeration_still_rejects_in_range_opacity(self):
        with self.assertRaises(contract.IndexRangeError):
            ranges.reconstruct_complete_index_range(profile=self.tree.profile,
                expected_root=self.tree.root, interval=self.all,
                frontier=count_frontier(self.tree, self.all), limits=ranges.IndexRangeLimits())

    def test_empty_interval_and_empty_tree_still_reconstruct(self):
        interval = contract.KeyInterval(key("11"), key("11"))
        self.assertEqual(self.verify(interval=interval).count, 0)
        empty = IndependentIndex([])
        observed = self.verify(tree=empty)
        self.assertEqual(observed.count, 0)
        self.assertEqual(observed.metrics.hashes, 1)
        self.assertEqual(observed.metrics.opened_nodes, 1)

    def test_partial_boundary_opacity_is_rejected(self):
        interval = contract.KeyInterval(key("10"), key("12"))
        with self.assertRaisesRegex(contract.IndexRangeError, "boundary"):
            self.verify(interval=interval, frontier=count_frontier(self.tree, self.all))

    def test_omission_count_digest_and_profile_tampering_fail(self):
        frontier = count_frontier(self.tree, self.all)
        wrong_count = (replace(frontier[0], count=frontier[0].count + 1), *frontier[1:])
        wrong_digest = (replace(frontier[0], digest=digest("not-the-node")), *frontier[1:])
        for altered in (frontier[1:], wrong_count, wrong_digest):
            with self.subTest(altered=altered), self.assertRaises(contract.IndexRangeError):
                self.verify(frontier=altered)
        with self.assertRaises(contract.IndexRangeError):
            self.verify(root=replace(self.tree.root, count=self.tree.root.count + 1))
        with self.assertRaises(contract.IndexRangeError):
            self.verify(profile=replace(self.tree.profile, index_id="wrong_index"))

    def test_duplicates_overlap_and_order_are_rejected(self):
        frontier = count_frontier(self.tree, self.all)
        for altered in ((frontier[0], *frontier), tuple(reversed(frontier)),
                        (frontier[0], self.tree.opaque("0f"), *frontier[1:])):
            with self.subTest(altered=altered), self.assertRaises(contract.IndexRangeError):
                self.verify(frontier=altered)

    def test_explicit_leaves_match_and_remain_bounded(self):
        frontier = self.tree.frontier(self.all)
        self.assertEqual(self.verify(frontier=frontier).count, len(frontier))
        with self.assertRaisesRegex(contract.IndexRangeError, "leaf budget"):
            self.verify(frontier=frontier, limits=ranges.IndexRangeLimits(max_leaves=1))
        interval = contract.KeyInterval(key("1"), key("2"))
        with self.assertRaisesRegex(contract.IndexRangeError, "outside"):
            self.verify(interval=interval, frontier=(self.tree.leaves[key("0")],))

    def test_poisoned_records_root_opacity_and_foreign_types_fail(self):
        frontier = count_frontier(self.tree, self.all)
        for record in (bypassed(frontier[0], count=True),
                       bypassed(frontier[0], prefix=""),
                       bypassed(frontier[0], count=contract.I64_MAX + 1), object()):
            with self.subTest(record=record), self.assertRaises(contract.IndexRangeError):
                self.verify(frontier=(record,))
        with self.assertRaises(contract.IndexRangeError):
            self.verify(frontier=list(frontier))
        with self.assertRaises(contract.IndexRangeError):
            self.verify(work=object())

    def test_local_resource_limits_remain_enforced(self):
        for limits in (ranges.IndexRangeLimits(max_entries=1),
                       ranges.IndexRangeLimits(max_input_bytes=1),
                       ranges.IndexRangeLimits(max_hashes=1)):
            with self.subTest(limits=limits), self.assertRaises(contract.IndexRangeError):
                self.verify(limits=limits)
        interval = contract.KeyInterval(key("10"), key("12"))
        with self.assertRaises(contract.IndexRangeError):
            self.verify(interval=interval, limits=ranges.IndexRangeLimits(max_opened_nodes=1))

    def test_cumulative_work_is_not_reset_between_queries(self):
        once = self.verify().metrics.hashes
        work = measured._ValidationWork(measured.QueryReadValidationLimits(max_hashes=2 * once - 1))
        self.verify(work=work)
        self.assertEqual(work.hash_work, once)
        self.assertGreater(work.input_bytes, self.verify().metrics.input_bytes)
        with self.assertRaises(measured.QueryReadWorkError):
            self.verify(work=work)

    def test_originals_are_detached_before_hash_callbacks(self):
        frontier = count_frontier(self.tree, self.all)
        original = frontier[0]
        count_before = self.tree.root.count
        branch = ranges.branch_node

        def mutate(*args, **kwargs):
            object.__setattr__(original, "count", 0)
            return branch(*args, **kwargs)

        with mock.patch.object(ranges, "branch_node", side_effect=mutate):
            self.assertEqual(self.verify(frontier=frontier).count, count_before)


if __name__ == "__main__":
    unittest.main()
