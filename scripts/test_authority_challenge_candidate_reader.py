#!/usr/bin/env python3
"""Synthetic leaf SQL, source projections and an independent counted tree.

The reader returns observations only; these controls assert no complete range,
primary proof, PostgreSQL snapshot, current root, signed parent or live route.
"""
from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_candidate_reader as candidate
from catchplate import authority_index_projection as projection
from catchplate import authority_index_reader as reader
from catchplate import authority_index_trace as trace_shapes
from catchplate import authority_query_read_work as measured
from catchplate import authority_transition_core as core
from catchplate.authority_index_contract import KeyInterval
from catchplate.authority_index_heads import CapturedIndexHead
from test_authority_index_range import IndependentIndex
from test_authority_radix_proof import sql_digest, sql_json, wire_digest, wire_json


class Trace:
    operation = "webauthn.challenge.maintain"

    def __init__(self):
        self.records = []

    def read(self, table, key):
        trace_shapes.validate_challenge_read_trace(self.operation, table, key)
        self.records.append((table, copy.deepcopy(key)))


class Cursor:
    """Literal leaf SELECT responder, never an SQL count/proof verdict."""

    def __init__(self, phase="expire", count=3):
        self.phase = phase
        profile = projection.profile_for(candidate.PHASE_INDEX[phase])
        leaves, self.rows = [], []
        for ordinal in range(count):
            identity = "00000000-0000-0000-0000-" + format(ordinal, "012x")
            row = dict(id=identity, challenge="synthetic-" + identity, challenge_type="registration",
                user_id="user", scope_key="scope", created_at="2026-01-01T00:00:00+00:00",
                expires_at="2026-01-01T00:05:00+00:00", retention_reference_mask=0,
                used_at="2026-01-01T00:01:00+00:00" if phase in {"old", "overflow"} else None)
            key_digest = wire_digest("catchplate.policyAuthorityBusinessKey/v1",
                b"webauthn_challenges", wire_json({"id": identity}))
            row_digest = sql_digest("catchplate.policyAuthorityAuthenticatedRow/v1",
                b"webauthn_challenges", sql_json(row))
            leaf = projection.project_row(profile.index_id, row,
                primary_key_digest=key_digest, primary_row_digest=row_digest)
            leaves.append(leaf)
            self.rows.append(dict(index_id=profile.index_id, projection_digest=profile.projection_digest,
                index_key=leaf.key, primary_id=identity, primary_key_digest=key_digest,
                primary_row_digest=row_digest, index_revision=7))
        self.index = IndependentIndex(leaves, profile=profile)
        self.calls = []
        self.transform = lambda rows: rows

    def execute(self, sql, parameters):
        if 'FROM "catchplate_metadata"."policy_authority_counted_index_leaves" AS leaf' not in sql:
            raise AssertionError("candidate fixture received a non-leaf SQL read")
        self.calls.append((sql, parameters))
        upper = parameters[2] if len(parameters) == 5 else None
        limit, offset = parameters[-2:]
        rows = sorted((copy.deepcopy(row) for row in self.rows
            if row["index_key"] >= parameters[1] and (upper is None or row["index_key"] < upper)),
            key=lambda row: row["index_key"], reverse=" DESC " in sql)
        self.pending = self.transform(rows[offset:offset + limit])
        return self

    def fetchmany(self, maximum):
        return self.pending[:maximum]


class ChallengeCandidateReaderTests(unittest.TestCase):
    def context(self, phase="expire", *, cursor=None, limits=None):
        cursor, trace = cursor or Cursor(phase), Trace()
        work = measured._ValidationWork(measured.QueryReadValidationLimits())
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work,
            limits=limits or reader._ReadAcquisitionLimits())
        profile = cursor.index.profile
        head = CapturedIndexHead(profile.index_id, "webauthn_challenges", projection.COUNTED_PROFILE,
            profile.projection_digest, projection.projection_manifest_digest(), 7, cursor.index.root)
        return cursor, trace, work, acquisition, head

    def acquire(self, context, *, phase=None, ordinal=0, base_offset=0, head=None):
        cursor, trace, work, acquisition, original_head = context
        return candidate.acquire_candidate_page(cursor, phase=phase or cursor.phase,
            head=original_head if head is None else head, interval=KeyInterval("0" * 160, None),
            base_offset=base_offset, ordinal=ordinal, trace=trace, work=work, acquisition=acquisition)

    def test_raw_source_phase_pages_preserve_exact_head_ids_and_order(self):
        for phase in candidate.PHASE_INDEX:
            with self.subTest(phase=phase):
                context = self.context(phase)
                encoded = self.acquire(context)
                self.assertIs(type(encoded), bytes)
                raw = json.loads(encoded)
                self.assertEqual(core.canonical_bytes(raw), encoded)
                self.assertEqual(set(raw), {"schema", "phase", "indexId", "projectionDigest",
                    "indexRevision", "rootDigest", "rootCount", "lower", "upper", "baseOffset", "ordinal", "leaves"})
                self.assertEqual(raw["schema"], candidate.SCHEMA)
                self.assertEqual(raw["rootDigest"], context[4].index_root.digest)
                actual = [leaf["primaryId"] for leaf in raw["leaves"]]
                expected = sorted((row["primary_id"] for row in context[0].rows), reverse=phase == "overflow")
                self.assertEqual(actual, expected)
                self.assertEqual(len(context[0].calls), 1)
                self.assertEqual(context[3].sql_reads, 1)
                self.assertEqual(len(context[1].records), 1)

    def test_fixed_pages_keep_full_limit_and_raw_empty_tail_without_completeness_claim(self):
        cursor = Cursor(count=257)
        pages = []
        for ordinal in range(3):
            context = self.context(cursor=cursor)
            raw = json.loads(self.acquire(context, ordinal=ordinal))
            pages.append(raw)
            self.assertEqual(cursor.calls[-1][1][-2:], (256, 256 * ordinal))
            self.assertNotIn("complete", raw)
        self.assertEqual([len(page["leaves"]) for page in pages], [256, 1, 0])
        identities = [leaf["primaryId"] for page in pages for leaf in page["leaves"]]
        self.assertEqual(len(set(identities)), 257)

    def test_offset_arithmetic_and_non_source_limits_are_closed(self):
        context = self.context("overflow")
        raw = json.loads(self.acquire(context, ordinal=24, base_offset=1000000))
        self.assertEqual(context[0].calls[-1][1][-2:], (256, 1006144))
        self.assertEqual(raw["leaves"], [])
        for phase, ordinal, offset in (("expire", 0, 1), ("scope", 0, 1),
                ("overflow", 25, 0), ("overflow", True, 0), ("overflow", 0, 1000001)):
            context = self.context(phase)
            with self.assertRaises(ValueError):
                self.acquire(context, ordinal=ordinal, base_offset=offset)
            self.assertEqual(context[0].calls, [])
            self.assertTrue(context[3].failed)

    def test_changed_order_identity_suffix_context_and_duplicate_members_are_refused(self):
        for change in ("order", "primary-key", "suffix", "revision", "duplicate", "custom-id"):
            with self.subTest(change=change):
                context = self.context()
                def alter(rows):
                    if change == "order":
                        return list(reversed(rows))
                    if change == "duplicate":
                        return [rows[0], rows[0]]
                    if change == "primary-key":
                        rows[0]["primary_key_digest"] = "sha256:" + "f" * 64
                    elif change == "suffix":
                        rows[0]["index_key"] = rows[0]["index_key"][:-1] + "1"
                    elif change == "revision":
                        rows[0]["index_revision"] += 1
                    elif change == "custom-id":
                        rows[0]["primary_id"] = "custom-id"
                    return rows
                context[0].transform = alter
                with self.assertRaises(ValueError):
                    self.acquire(context)
                self.assertTrue(context[3].failed)

    def test_original_source_context_and_budget_cannot_be_replaced(self):
        context = self.context()
        with self.assertRaises(ValueError):
            self.acquire(context, head=replace(context[4], projection_manifest_digest="sha256:" + "f" * 64))
        self.assertEqual(context[0].calls, [])
        context = self.context(limits=reader._ReadAcquisitionLimits(max_transport_bytes=100))
        with self.assertRaises(ValueError):
            self.acquire(context)
        calls = len(context[0].calls)
        with self.assertRaises(ValueError):
            self.acquire(context)
        self.assertEqual(len(context[0].calls), calls)
        context = self.context()
        changed = (context[0], context[1], measured._ValidationWork(measured.QueryReadValidationLimits()), *context[3:])
        with self.assertRaises(ValueError):
            self.acquire(changed)
        self.assertEqual(context[0].calls, [])

    def test_new_marker_is_exact_without_widening_old_candidate_shape(self):
        context = self.context("scope")
        self.acquire(context)
        table, marker = context[1].records[0]
        for field, value in (("offset", 1), ("limit", 255), ("descending", 0),
                             ("ordinal", True), ("baseOffset", 1), ("extra", None)):
            altered = dict(marker, **{field: value})
            with self.assertRaises(trace_shapes.IndexTraceError):
                trace_shapes.validate_challenge_read_trace(context[1].operation, table, altered)
        old = {key: value for key, value in marker.items() if key not in {"baseOffset", "ordinal"}}
        old["profile"] = trace_shapes.CHALLENGE_CANDIDATE_READ_PROFILE
        with self.assertRaises(trace_shapes.IndexTraceError):
            trace_shapes.validate_challenge_read_trace(context[1].operation, table, old)


if __name__ == "__main__":
    unittest.main()
