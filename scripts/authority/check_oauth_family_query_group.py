"""Source assertions for the fixed two-root group; not run in source-only work."""
from dataclasses import replace
import unittest

from serverware import authority_oauth_family_query_group as group
from serverware import authority_transition_core as core


class FamilyQueryGroupChecks(unittest.TestCase):
    operation = "oauth.pending.activate"

    def test_old_only_capacity32_keeps_both_real_reads(self):
        queries = group.queries(self.operation)
        self.assertEqual(group.declared_rows(self.operation, queries), 34)
        self.assertEqual(sum(query.work_units for query in queries), 66)
        acquisition = group.Acquisition(self.operation, queries)
        for query, count in zip(queries, (32, 0)):
            acquisition.before(query)
            acquisition.record(query, count)
        acquisition.finish()

    def test_missing_member_is_not_a_budget_discount(self):
        with self.assertRaises(core.TransitionKernelError):
            group.declared_rows(self.operation, group.queries(self.operation)[:1])

    def test_every_semantic_query_member_is_fixed(self):
        left, right = group.queries(self.operation)
        for changed in (replace(left, maximum_rows=32), replace(left, work_units=1),
                replace(left, predicates=(core.QueryPredicate("id", "eq", "selected"),)),
                replace(left, order_by=(core.QueryOrder("id", descending=True),)),
                replace(left, proof_primitive="primary-key-row")):
            with self.assertRaises(core.TransitionKernelError):
                group.declared_rows(self.operation, (changed, right))

    def test_combined_overflow_refuses_even_when_each_read_fits(self):
        queries = group.queries(self.operation)
        acquisition = group.Acquisition(self.operation, queries)
        acquisition.before(queries[0]); acquisition.record(queries[0], 17)
        acquisition.before(queries[1])
        with self.assertRaises(core.TransitionKernelError):
            acquisition.record(queries[1], 16)

    def test_individual_sentinel_is_not_truncated(self):
        queries = group.queries(self.operation)
        acquisition = group.Acquisition(self.operation, queries)
        with self.assertRaises(core.TransitionKernelError):
            acquisition.record(queries[0], 33)

    def test_other_query_cannot_precede_the_two_observations(self):
        queries = group.queries(self.operation)
        acquisition = group.Acquisition(self.operation, queries)
        with self.assertRaises(core.TransitionKernelError):
            acquisition.before(queries[1])


if __name__ == "__main__":
    unittest.main()
