#!/usr/bin/env python3
"""Count-reader controls with real reconstruction and inert stored-node SQL.

An independent counted-tree hash oracle supplies rows, not success assertions.
This is not PostgreSQL, source-index installation or signed-plan acceptance.
"""
from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_index_contract as contract
from catchplate import authority_index_count_reader as counter
from catchplate import authority_index_projection as projection
from catchplate import authority_index_reader as reader
from catchplate import authority_query_read_work as measured
from scripts.test_authority_index_range import IndependentIndex, NIBBLES, TOP, WIDTH, digest, leaf


def key(number):
    return format(number, "0" + str(WIDTH) + "x")


def bounds(low, high):
    return contract.KeyInterval(key(low), None if high == TOP else key(high))


def cover_oracle(interval):
    """Independent greedy aligned-block tiling of the three interval regions."""
    low = int(interval.lower, 16)
    high = TOP if interval.upper is None else int(interval.upper, 16)
    if low == high:
        return tuple(NIBBLES)
    result = []
    for start, end in ((0, low), (low, high), (high, TOP)):
        while start < end:
            power, size = 0, 1
            while size * 16 <= end - start and size * 16 < TOP and start % (size * 16) == 0:
                power += 1
                size *= 16
            result.append(key(start)[:WIDTH - power])
            start += size
    return tuple(result)


class Trace:
    def __init__(self):
        self.records = []
        self.callback = None

    def read(self, table, selection):
        self.records.append((table, selection))
        if self.callback is not None:
            self.callback()


class Cursor:
    def __init__(self, tree, revision=11):
        self.rows = {(len(prefix), prefix): dict(index_id=tree.profile.index_id,
            projection_digest=tree.profile.projection_digest, depth=len(prefix),
            path_prefix=prefix, node_digest=node[0], subtree_count=node[1],
            index_revision=revision)
            for prefix, node in tree.nodes.items() if prefix and node[1]}
        self.calls = []
        self.transform = lambda rows: rows

    def execute(self, sql, parameters):
        self.calls.append((sql, parameters))
        identities = tuple(zip(parameters[:-2:2], parameters[1:-2:2]))
        self.result = self.transform([dict(self.rows[value])
            for value in identities if value in self.rows])
        return self

    def fetchmany(self, maximum):
        return self.result[:maximum]


class AuthorityIndexCountReaderTests(unittest.TestCase):
    def setUp(self):
        self.profile = projection.profile_for("webauthn_registration_unused_global")
        self.tree = IndependentIndex([leaf(key(number)) for number in (0, 1, 15, 16, 31, 255, 300)],
            profile=self.profile)
        self.all = bounds(0, TOP)

    def context(self, tree=None, *, limits=None):
        tree = self.tree if tree is None else tree
        cursor, trace = Cursor(tree), Trace()
        work = measured._ValidationWork(measured.QueryReadValidationLimits())
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work,
            limits=reader._ReadAcquisitionLimits() if limits is None else limits)
        return cursor, trace, work, acquisition

    def acquire(self, context, *, tree=None, interval=None, profile=None, revision=11):
        tree = self.tree if tree is None else tree
        cursor, trace, work, acquisition = context
        return counter.acquire_count_frontier(cursor,
            profile=tree.profile if profile is None else profile,
            index_revision=revision, expected_root=tree.root,
            interval=self.all if interval is None else interval,
            trace=trace, work=work, acquisition=acquisition)

    def test_prefix_cover_matches_independent_tiling_and_fixed_bounds(self):
        for low, high in ((0, TOP), (0, 0), (16, 16), (16, 17), (1, TOP - 1), (15, 300)):
            with self.subTest(low=low, high=high):
                interval = bounds(low, high)
                cover = counter.count_prefixes(interval)
                self.assertEqual(cover, cover_oracle(interval))
                self.assertLessEqual(len(cover), counter.MAX_PREFIXES)
                self.assertTrue(all(1 <= len(prefix) <= WIDTH for prefix in cover))

    def test_actual_counts_frontier_and_guarded_node_only_sql(self):
        for interval in (self.all, bounds(15, 32), bounds(2, 14), bounds(17, 17)):
            with self.subTest(interval=interval):
                context = self.context()
                observed = self.acquire(context, interval=interval)
                self.assertEqual(observed.count, len(self.tree.matches(interval)))
                self.assertEqual(observed.root, self.tree.root)
                self.assertEqual(observed.metrics.sql_reads, len(context[0].calls))
                self.assertEqual(observed.metrics.node_reads, len(context[1].records))
                self.assertEqual(observed.metrics.business_key_hashes, 0)
                self.assertTrue(all(type(item) is contract.OpaqueSubtree for item in observed.frontier))
                for sql, parameters in context[0].calls:
                    self.assertIn('"policy_authority_counted_index_nodes"', sql)
                    self.assertIn("pg_catalog.pg_typeof", sql)
                    self.assertNotIn("COUNT(*)", sql)
                    self.assertNotIn("index_revision =", sql)
                    self.assertLessEqual(len(parameters), 2 * reader.MAX_NODE_IDENTITIES + 2)
                self.assertTrue(all(row[1]["profile"] == counter.READ_PROFILE
                    for row in context[1].records))

    def test_large_population_uses_one_node_not_primary_enumeration(self):
        tree = IndependentIndex([leaf(key(number)) for number in range(300)], profile=self.profile)
        observed = self.acquire(self.context(tree), tree=tree)
        self.assertEqual(observed.count, 300)
        self.assertEqual(observed.metrics.returned_rows, 1)
        self.assertEqual(observed.metrics.range_metrics.leaves, 0)
        self.assertEqual(observed.metrics.requested_prefixes, 16)

    def test_empty_root_zero_revision_and_worst_boundary_batches(self):
        tree = IndependentIndex([], profile=self.profile)
        context = self.context(tree)
        observed = self.acquire(context, tree=tree, interval=bounds(1, TOP - 1), revision=0)
        self.assertEqual(observed.count, 0)
        self.assertEqual(observed.metrics.returned_rows, 0)
        self.assertEqual(observed.metrics.sql_reads, counter.MAX_SQL_READS)
        with self.assertRaises(contract.IndexRangeError):
            self.acquire(self.context(), revision=0)

    def test_missing_or_corrupt_nodes_fail_and_poison_original_acquisition(self):
        for transform in (
            lambda rows: [],
            lambda rows: [*rows, dict(rows[0])],
            lambda rows: [{**row, "subtree_count": row["subtree_count"] + 1} for row in rows],
            lambda rows: [{**row, "node_digest": digest("incorrect")} for row in rows],
            lambda rows: [{**row, "index_revision": 12} for row in rows],
            lambda rows: [{**row, "projection_digest": digest("incorrect")} for row in rows],
            lambda rows: [{**row, "depth": True} for row in rows],
            lambda rows: [{**row, "unexpected": 1} for row in rows],
        ):
            context = self.context()
            context[0].transform = transform
            with self.assertRaises(contract.IndexRangeError):
                self.acquire(context)
            self.assertTrue(context[3].failed)
            calls = len(context[0].calls)
            with self.assertRaises(contract.IndexRangeError):
                self.acquire(context)
            self.assertEqual(len(context[0].calls), calls)

    def test_source_profile_substitution_refused_before_sql(self):
        context = self.context()
        with self.assertRaises(contract.IndexRangeError):
            self.acquire(context, profile=replace(self.profile, projection_digest=digest("foreign")))
        self.assertEqual(context[0].calls, [])
        self.assertTrue(context[3].failed)

    def test_shared_acquisition_caps_are_not_reset(self):
        context = self.context(limits=reader._ReadAcquisitionLimits(max_sql_reads=1))
        self.acquire(context)
        with self.assertRaises(contract.IndexRangeError):
            self.acquire(context)
        for limits in (reader._ReadAcquisitionLimits(max_parameter_bytes=1),
                       reader._ReadAcquisitionLimits(max_transport_bytes=1)):
            with self.assertRaises(contract.IndexRangeError):
                self.acquire(self.context(limits=limits))

    def test_replaced_work_and_swallowed_reentrancy_are_poisoning(self):
        context = self.context()
        other = measured._ValidationWork(measured.QueryReadValidationLimits())
        with self.assertRaises(contract.IndexRangeError):
            self.acquire((context[0], context[1], other, context[3]))
        self.assertEqual(context[0].calls, [])
        context = self.context()

        def swallowed():
            with self.assertRaises(contract.IndexRangeError):
                self.acquire(context)

        context[1].callback = swallowed
        with self.assertRaises(contract.IndexRangeError):
            self.acquire(context)
        self.assertTrue(context[3].failed)
        self.assertEqual(context[0].calls, [])


if __name__ == "__main__":
    unittest.main()
