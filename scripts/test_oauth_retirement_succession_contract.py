"""Deferred synthetic contract regressions, not protected/runtime admission.

Authored for a later consolidated test run. No test was executed in this source
slice. Positive scalar fixtures do not prove signatures, roots or kernel effects.
"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import authority_contract
from catchplate import authority_oauth_retirement_succession as p
from catchplate import authority_oauth_retirement_succession_snapshots as snapshots
from catchplate import authority_transition_oauth_retirement_succession as transition
from catchplate import authority_oauth_family_retirement as family
from catchplate import authority_oauth_measured_pending_retirement as pending


def roots():
    return [{"part": part, "root": {"table": table, "rootRevision": 0,
        "rootDigest": "sha256:" + "1" * 64, "leafCount": 0}}
        for part, table in sorted(p.SNAPSHOT_PARTS.items())]


class CompletePartContract(unittest.TestCase):
    def test_closed_map_and_unchanged_global_ceiling(self):
        self.assertEqual(len(p.SNAPSHOT_PARTS), 28)
        self.assertEqual(authority_contract.MAX_QUERY_PROOFS, 256)
        self.assertEqual(p.inventory_roots(roots()), roots())

    def test_missing_or_duplicate_part_refused(self):
        value = roots()
        with self.assertRaises(ValueError):
            p.inventory_roots(value[:-1])
        value[-1] = value[0]
        with self.assertRaises(ValueError):
            p.inventory_roots(value)

    def test_forged_member_table_refused(self):
        value = roots(); value[0]["root"]["table"] = "webauthn_credentials"
        with self.assertRaises(ValueError):
            p.inventory_roots(value)

    def test_each_actual_query_is_unfiltered_and_sentinel_bounded(self):
        identifier = "7d661f19-1fbe-4b1f-8f67-7b866588515f"
        for part, table in p.SNAPSHOT_PARTS.items():
            result = snapshots.queries("oauth.succession.snapshot." + part, identifier)
            self.assertEqual(len(result), 2)
            self.assertEqual(result[1].table, table)
            self.assertEqual(result[1].predicates, ())
            self.assertEqual(result[1].maximum_rows, p.snapshot_limit(part) + 1)
            self.assertEqual(result[1].proof_primitive, "bounded-limit-plus-one")
        with self.assertRaises(ValueError):
            snapshots.queries("oauth.succession.snapshot.webauthn_credentials", identifier)

    def test_part_population_overflow_refused(self):
        value = roots(); value[0]["root"]["leafCount"] = p.snapshot_limit(value[0]["part"]) + 1
        with self.assertRaises(ValueError):
            p.inventory_roots(value)

    def test_old_only_32_and_combined_overflow(self):
        # Pure local capacity regression only. Neither this stand-in nor this
        # grant is an actual RetainedGraph or an admitted protected context.
        class Fixture:
            def __init__(self, extra):
                self.extra = extra

            def rows(self, table):
                if table == family.TABLE:
                    return [{"provider_id": "x"} for _ in range(32)]
                if table == pending.FAMILY_TABLE:
                    return [{"provider_id": "x"} for _ in range(self.extra)]
                return []
        grant = {"predecessors": [], "providerId": "google", "scope": {"kind": "provider"}}
        transition._predecessor_coverage(Fixture(0), grant)
        with self.assertRaises(ValueError):
            transition._predecessor_coverage(Fixture(1), grant)


if __name__ == "__main__":
    unittest.main()
