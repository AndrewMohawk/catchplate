#!/usr/bin/env python3
"""Recording-cursor component controls: no SQL server or proof admission.

The literal synthetic node records exercise real acquisition/encoding/budgets.
They are deliberately not claimed to reconstruct a genuine authenticated root.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_frontier_reader as frontier
from catchplate import authority_index_projection as projection
from catchplate import authority_index_reader as reader
from catchplate import authority_query_read_work as measured
from catchplate import authority_transition_core as core
from catchplate.authority_index_contract import CountedNode
from catchplate.authority_index_heads import CapturedIndexHead


class Trace:
    operation = "webauthn.challenge.maintain"

    def __init__(self):
        self.records = []
        self.callback = None

    def read(self, table, marker):
        self.records.append((table, copy.deepcopy(marker)))
        if self.callback is not None:
            self.callback()


class Cursor:
    """Synthetic immediate-child SELECT responder, not a database authority."""

    def __init__(self, profile):
        self.profile, self.calls, self.fetches = profile, [], []
        self.transform = lambda rows: rows
        self.closed = False

    def execute(self, sql, parameters):
        self.calls.append((sql, parameters))
        assert parameters[-2:] == (self.profile.index_id, 257)
        assert len(parameters[:-2]) % 3 == 0
        rows = []
        for depth, lower, upper in zip(parameters[:-2:3], parameters[1:-2:3], parameters[2:-2:3]):
            assert lower[:-1] == upper[:-1] and lower[-1] == "0" and upper[-1] == "f"
            for digit in "0123456789abcdef":
                rows.append(dict(index_id=self.profile.index_id,
                    projection_digest=self.profile.projection_digest, depth=depth,
                    path_prefix=lower[:-1] + digit, node_digest="sha256:" + "a" * 64,
                    subtree_count=1, index_revision=3))
        self.pending = self.transform(sorted(rows, key=lambda row: row["path_prefix"]))
        return self

    def fetchmany(self, maximum):
        self.fetches.append(maximum)
        return self.pending[:maximum]

    def close(self):
        self.closed = True
        raise AssertionError("reader must not close its caller's cursor")


class ChallengeFrontierReaderTests(unittest.TestCase):
    def context(self, *, identity=frontier.INDEX_IDS[0], targets=None, limits=None):
        profile = projection.profile_for(identity)
        head = CapturedIndexHead(identity, "webauthn_challenges", projection.COUNTED_PROFILE,
            profile.projection_digest, projection.projection_manifest_digest(), 7,
            CountedNode("sha256:" + "b" * 64, 256))
        work = measured._ValidationWork(measured.QueryReadValidationLimits())
        targets = ("0" * 160,) if targets is None else targets
        geometry = frontier.capture_frontier_geometry(head=head, target_keys=targets, work=work)
        cursor, trace = Cursor(profile), Trace()
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work,
            limits=limits or reader._ReadAcquisitionLimits())
        return cursor, trace, work, acquisition, geometry

    def page(self, context, ordinal=0, **changes):
        cursor, trace, work, acquisition, geometry = context
        arguments = dict(geometry=geometry, ordinal=ordinal, trace=trace, work=work, acquisition=acquisition)
        arguments.update(changes)
        return frontier.acquire_frontier_page(cursor, **arguments)

    def test_actual_range_parameters_and_canonical_pages_cover_exact_geometry(self):
        context = self.context()
        cursor, trace, work, acquisition, _geometry = context
        expected = tuple("0" * depth for depth in range(160))
        self.assertEqual(frontier.frontier_parents(("0" * 160,)), expected)
        geometry_work = measured._ValidationWork(measured.QueryReadValidationLimits())
        self.assertEqual(frontier.frontier_parents(("0" * 160,), work=geometry_work), expected)
        self.assertGreater(geometry_work.input_bytes, 0)
        with self.assertRaises(reader.IndexReadError):
            frontier.frontier_parents(("0" * 160,), work={})
        before = work.input_bytes
        pages = [json.loads(self.page(context, ordinal)) for ordinal in range(10)]
        self.assertGreater(work.input_bytes, before)
        self.assertEqual([parent for page in pages for parent in page["parents"]], list(expected))
        for ordinal, page in enumerate(pages):
            self.assertEqual(set(page), {"schema", "indexId", "projectionDigest", "indexRevision",
                "rootDigest", "rootCount", "ordinal", "parentCount", "parents", "children"})
            self.assertEqual(page["schema"], frontier.SCHEMA)
            self.assertEqual((page["ordinal"], page["parentCount"]), (ordinal, 160))
            self.assertEqual(len(page["children"]), 256)
            self.assertTrue(all(child["prefix"][:-1] in page["parents"] for child in page["children"]))
            sql, parameters = cursor.calls[ordinal]
            self.assertEqual(len(parameters), 50)  # 16 ranges, not 240 absent siblings.
            self.assertIn('node.depth = requested.depth', sql)
            self.assertIn('node.path_prefix COLLATE "C" >= requested.lower_prefix', sql)
            self.assertIn('node.path_prefix COLLATE "C" <= requested.upper_prefix', sql)
            self.assertIn('WHERE node.index_id COLLATE "C" = %s', sql)
            self.assertNotIn("OFFSET", sql)
            self.assertNotIn("COUNT(", sql)
            self.assertEqual(trace.records[ordinal][1]["parents"], page["parents"])
        self.assertEqual((acquisition.sql_reads, acquisition.returned_rows), (10, 2560))
        self.assertEqual(cursor.fetches, [257] * 10)
        self.assertFalse(cursor.closed)
        fresh = self.context()
        raw = self.page(fresh)
        self.assertIs(type(raw), bytes)
        self.assertEqual(raw, core.canonical_bytes(json.loads(raw)))
        self.assertLessEqual(len(raw), frontier.MAX_RAW_BYTES)

    def test_all_nine_profiles_and_empty_targets_keep_source_key_codecs(self):
        self.assertEqual(set(frontier.INDEX_IDS), set(projection.index_ids_for_table("webauthn_challenges")))
        self.assertEqual(frontier.frontier_parents(()), ("",))
        for identity in frontier.INDEX_IDS:
            with self.subTest(identity=identity):
                context = self.context(identity=identity, targets=())
                page = json.loads(self.page(context))
                self.assertEqual((page["parentCount"], page["parents"]), (1, [""]))
                self.assertEqual(len(page["children"]), 16)
        # The old profiles accept their existing arbitrary 160-hex codec;
        # no new generated-ID suffix predicate is imposed by the collector.
        for identity in frontier.INDEX_IDS[:2]:
            self.page(self.context(identity=identity, targets=("f" * 160,)))
        for targets in ([], ("a" * 159,), ("A" * 160,), ("b" * 160, "a" * 160),
                        ("a" * 160, "a" * 160), tuple(f"{n:0160x}" for n in range(513))):
            with self.subTest(targets_type=type(targets).__name__, length=len(targets)):
                with self.assertRaises(reader.IndexReadError):
                    frontier.frontier_parents(targets)

    def test_bad_rows_or_overflow_poison_the_existing_acquisition(self):
        def replace_first(rows, **fields):
            rows[0].update(fields)
            return rows
        variants = (
            lambda rows: rows + [dict(rows[-1])],
            lambda rows: [rows[0], rows[0], *rows[2:]],
            lambda rows: replace_first(rows, index_revision=8),
            lambda rows: replace_first(rows, subtree_count=0),
            lambda rows: replace_first(rows, path_prefix="ab", depth=2),
            lambda rows: replace_first(rows, projection_digest="sha256:" + "c" * 64),
        )
        for transform in variants:
            context = self.context()
            context[0].transform = transform
            with self.assertRaises(reader.IndexReadError):
                self.page(context)
            self.assertTrue(context[3].failed)
            with self.assertRaises(reader.IndexReadError):
                self.page(context)

    def test_original_pair_geometry_and_limits_fail_closed_without_new_allowance(self):
        for ordinal in (-1, True, 10):
            context = self.context()
            with self.assertRaises(reader.IndexReadError):
                self.page(context, ordinal)
            self.assertEqual(context[0].calls, [])
        context = self.context()
        with self.assertRaises(reader.IndexReadError):
            self.page(context, geometry={"parents": [""]})
        context = self.context(limits=reader._ReadAcquisitionLimits(max_sql_reads=1))
        self.page(context)
        with self.assertRaises(reader.IndexReadError):
            self.page(context, 1)
        self.assertEqual(len(context[0].calls), 1)
        context = self.context()
        replacement = measured._ValidationWork(measured.QueryReadValidationLimits())
        with self.assertRaises(reader.IndexReadError):
            self.page(context, work=replacement)
        self.assertEqual(context[0].calls, [])
        context = self.context()
        def cancel():
            raise KeyboardInterrupt()
        context[1].callback = cancel
        with self.assertRaises(KeyboardInterrupt):
            self.page(context)
        self.assertTrue(context[3].failed)
        self.assertEqual(context[0].calls, [])
        self.assertFalse(context[0].closed)


if __name__ == "__main__":
    unittest.main()
