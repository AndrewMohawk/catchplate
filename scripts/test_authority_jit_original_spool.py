#!/usr/bin/env python3
"""Bounded raw-spool controls with a genuine synthetic compound replay.

These controls do not exercise native PostgreSQL capture or durable custody.
One genuine fixture/replay supplies raw documents; clocks are explicit doubles.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_jit_original_spool as source
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_jit_compound import DEADLINE, originals, replay
from test_authority_jit_connected_originals import canonical, connected_fixture, meter


class JitOriginalSpoolControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = connected_fixture()
        cls.pages, _digest = originals(cls.case)
        with patch.object(source.time, "monotonic_ns", return_value=100):
            cls.observation = replay(cls.case, cls.pages)

    def capture(self):
        spool = source._JitOriginalSpool(original_deadline_ns=DEADLINE, work=meter())
        for (kind, ordinal), raw in self.pages.items():
            self.assertIsNone(spool.retain(kind, ordinal, raw, meter()))
        return spool

    def seal(self, spool, *, context=None, manifest=None, work=None):
        return spool.seal(context_bytes=self.observation.context_bytes if context is None else context,
            manifest_bytes=self.observation.original_manifest_bytes if manifest is None else manifest,
            work=meter() if work is None else work)

    def test_exact_capture_seal_and_independent_replay_return_literal_originals(self):
        with patch.object(source.time, "monotonic_ns", return_value=100):
            spool = self.capture()
            self.assertIsNone(self.seal(spool))
            self.assertEqual(spool.keys(work=meter()), tuple(self.pages))
            for key, raw in self.pages.items():
                self.assertIs(spool.read(*key, meter()), raw)
            repeated = replay(self.case, self.pages, read=spool.read)
            self.assertEqual(repeated.context_bytes, self.observation.context_bytes)
            self.assertEqual(repeated.original_manifest_bytes, self.observation.original_manifest_bytes)
            self.assertEqual(repeated.total_acquisition, source.compound.PhysicalMetrics(0, 0, 0, 0))

    def test_seal_uses_held_immutable_digests_not_a_second_full_raw_parent_walk(self):
        with patch.object(source.time, "monotonic_ns", return_value=100):
            spool = self.capture()
            work = meter()
            with patch.object(source, "_digest", side_effect=AssertionError("unexpected raw rehash")):
                self.seal(spool, work=work)
            # Three genuine source-binding hashes, context + seed, then one
            # chain step per original. The global source projection is larger
            # than a 4MiB test guess; its real work stays on the unchanged
            # caller allowance, with no extra body hash at seal.
            self.assertEqual(work.hash_work, len(self.pages) + 5)
            self.assertLessEqual(work.input_bytes, work.limits.max_input_bytes)
            actual = meter()
            key = next(iter(self.pages))
            spool.read(*key, actual)
            self.assertEqual(actual.hash_work, 1)
            self.assertGreaterEqual(actual.input_bytes, len(self.pages[key]))

    def test_invalid_order_exact_types_and_body_caps_poison_capture(self):
        first = self.pages["primary-chunk", 0]
        for kind, ordinal, raw in (("primary-proof", 0, b"{}"),
                ("primary-chunk", 1, first), ("primary-chunk", True, first),
                ("primary-chunk", 0, bytearray(first)), ("unknown", 0, first),
                ("primary-chunk", 0, b"x" * (source.compound.frames.MAX_CHUNK_BYTES + 1))):
            with self.subTest(kind=kind, ordinal=ordinal, raw_type=type(raw).__name__), \
                    patch.object(source.time, "monotonic_ns", return_value=100):
                spool = source._JitOriginalSpool(original_deadline_ns=DEADLINE, work=meter())
                with self.assertRaises(ValueError):
                    spool.retain(kind, ordinal, raw, meter())
                with self.assertRaises(ValueError):
                    spool.retain("primary-chunk", 0, first, meter())

    def test_absent_chunk_cannot_have_a_second_chunk_or_duplicate_proof(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate), patch.object(source.time, "monotonic_ns", return_value=100):
                spool = source._JitOriginalSpool(original_deadline_ns=DEADLINE, work=meter())
                spool.retain("primary-chunk", 0, b"[]", meter())
                if duplicate:
                    spool.retain("primary-proof", 0, b"{}", meter())
                with self.assertRaises(ValueError):
                    spool.retain("primary-proof" if duplicate else "primary-chunk",
                        0 if duplicate else 1, b"{}", meter())

    def test_partial_capture_and_early_read_cannot_be_sealed_or_retried(self):
        for operation in ("seal", "read", "keys"):
            with self.subTest(operation=operation), patch.object(source.time, "monotonic_ns", return_value=100):
                spool = source._JitOriginalSpool(original_deadline_ns=DEADLINE, work=meter())
                with self.assertRaises(ValueError):
                    if operation == "seal": self.seal(spool)
                    elif operation == "read": spool.read("primary-chunk", 0, meter())
                    else: spool.keys(work=meter())
                with self.assertRaises(ValueError):
                    spool.retain("primary-chunk", 0, b"[]", meter())

    def test_manifest_substitution_and_context_clock_canonicality_are_rejected(self):
        for defect in ("digest", "order", "count", "chain", "deadline", "whitespace"):
            with self.subTest(defect=defect), patch.object(source.time, "monotonic_ns", return_value=100):
                spool = self.capture()
                manifest = json.loads(self.observation.original_manifest_bytes)
                context = json.loads(self.observation.context_bytes)
                if defect == "digest": manifest["originals"][0]["digest"] = "sha256:" + "0" * 64
                elif defect == "order": manifest["originals"][0:2] = reversed(manifest["originals"][0:2])
                elif defect == "count": manifest["originalCount"] += 1
                elif defect == "chain": manifest["originalChainDigest"] = "sha256:" + "0" * 64
                elif defect == "deadline": context["originalDeadlineNs"] += 1
                context_raw = canonical(context) + (b" " if defect == "whitespace" else b"")
                with self.assertRaises(ValueError):
                    self.seal(spool, context=context_raw, manifest=canonical(manifest))
                with self.assertRaises(ValueError):
                    self.seal(spool)

    def test_original_clock_and_process_cannot_be_renewed(self):
        for clock in (99, DEADLINE):
            with self.subTest(clock=clock):
                with patch.object(source.time, "monotonic_ns", return_value=100):
                    spool = self.capture()
                with patch.object(source.time, "monotonic_ns", return_value=clock):
                    with self.assertRaises(ValueError): self.seal(spool)
                with patch.object(source.time, "monotonic_ns", return_value=100):
                    with self.assertRaises(ValueError): self.seal(spool)
        with patch.object(source.time, "monotonic_ns", return_value=100):
            spool = self.capture()
            with patch.object(source.os, "getpid", return_value=spool._process[0] + 1):
                with self.assertRaises(ValueError): self.seal(spool)

    def test_work_is_debited_before_hash_and_failed_capture_is_not_retryable(self):
        with patch.object(source.time, "monotonic_ns", return_value=100):
            spool = source._JitOriginalSpool(original_deadline_ns=DEADLINE, work=meter())
            work = _ValidationWork(QueryReadValidationLimits(max_input_bytes=8191))
            with patch.object(source, "_digest", wraps=source._digest) as digest:
                with self.assertRaises(ValueError):
                    spool.retain("primary-chunk", 0, b"[]", work)
                digest.assert_not_called()
            with self.assertRaises(ValueError): spool.retain("primary-chunk", 0, b"[]", meter())


if __name__ == "__main__":
    unittest.main()
