#!/usr/bin/env python3
"""UNRUN genuine raw replay and fixed-pass ownership controls.

Independent synthetic trees and a real ES256 assertion prepare raw originals;
no successful receipt/result DTO enters run_pass. Time is explicitly doubled.
These controls do not establish native PG/TLS/currentness, signed custody,
all-input capacity, public routing or deployed producer acceptance.
"""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_jit_compound as source
from catchplate.authority_query_read_work import QueryReadValidationLimits
from test_authority_jit_connected_originals import (
    connected_fixture, capture_seven, first_receipt, canonical, meter,
)
from test_authority_jit_primary_chunks import frames, native


DEADLINE = 1_000_000


def originals(case):
    pages = {}
    for slot, query in enumerate(case["queries"]):
        tree = case["trees"][query.table]
        selected = tree.selected(query.absent_key)
        chunks = ([record] for record in frames(native(selected["row"]))) if selected["present"] else ([],)
        for ordinal, values in enumerate(chunks):
            pages["primary-chunk", slot * source.rows.chunks.MAX_ROW_DATA_CHUNKS + ordinal] = canonical(values)
        pages["primary-proof", slot] = source.frames.encode_proof(tree.proof(selected), work=meter())
    # This is fixture preparation, not an input receipt token: obtain the
    # eighth key only from the actual first seven membership/ES256 stages.
    _owner, captured, _chunks = capture_seven(case)
    _receipt, digest = first_receipt(captured, case["assertion_policy"])
    query = source.source.receipt.receipt_query(digest)
    tree = case["trees"][query.table]
    selected = tree.selected(query.absent_key)
    pages["primary-proof", 7] = source.frames.encode_proof(tree.proof(selected), work=meter())
    for ordinal, value in enumerate(case["index_inputs"]):
        pages["index-frontier", ordinal] = source.frames.encode_index(value, work=meter())
    return pages, digest


def replay(case, pages, *, read=None, check=None, deadline=DEADLINE):
    return source.run_pass(request=case["request"], assertion_policy=case["assertion_policy"],
        business_before_roots=case["business_before_roots"],
        authorization_before_roots=case["authorization_before_roots"],
        counted_before_heads=case["counted_before_heads"], database_cutoff_us=case["database_cutoff_us"],
        original_deadline_ns=deadline, cursor=None, trace=None,
        check=(lambda stage: None) if check is None else check,
        read_original=(lambda kind, ordinal, work: pages[kind, ordinal]) if read is None else read)


class JitCompoundControls(unittest.TestCase):
    def test_source_handler_uses_actual_bounded_json_projection_after_reservation(self):
        actual = meter()
        digest = source.source._handler_contract_on_work(actual)
        self.assertEqual(digest, source.source.authority.handler_contract_digest(source.OPERATION))
        self.assertGreater(actual.input_bytes, 4 * 16384)
        self.assertEqual(actual.hash_work, 1)
        with patch.object(source.source.authority, "_operation_manifest_entry",
                wraps=source.source.authority._operation_manifest_entry) as projection:
            with self.assertRaises(ValueError):
                source.source._handler_contract_on_work(source._ValidationWork(
                    QueryReadValidationLimits(max_input_bytes=4 * 16384 - 1)))
            projection.assert_not_called()

    def test_actual_full_raw_replay_recomputes_every_stage_and_has_no_fabricated_sql_metrics(self):
        case = connected_fixture()
        pages, digest = originals(case)
        requested = []
        def read(kind, ordinal, work):
            requested.append((kind, ordinal))
            return pages[kind, ordinal]
        with patch.object(source.time, "monotonic_ns", return_value=100):
            actual = replay(case, pages, read=read)
            repeated = replay(case, pages)
        self.assertEqual(actual.transition.result["assertion_receipt_digest"], digest)
        self.assertEqual(len(actual.transition.mutations), 3)
        self.assertEqual(len(actual.indexed_result.after_heads), 12)
        self.assertEqual(actual.indexed_result.metrics.new_row_hashes, 2)
        self.assertEqual(actual.context_bytes, repeated.context_bytes)
        self.assertEqual(actual.original_manifest_bytes, repeated.original_manifest_bytes)
        self.assertEqual(set(requested), set(pages))
        self.assertEqual(len(requested), len(pages))
        self.assertEqual(actual.total_acquisition, source.PhysicalMetrics(0, 0, 0, 0))
        self.assertTrue(all(stage.physical is None for stage in actual.stages))
        self.assertEqual(actual.total_original_bytes, sum(map(len, pages.values())))
        self.assertEqual(actual.total_original_bytes, sum(stage.original_bytes for stage in actual.stages))
        self.assertEqual(actual.total_work.input_bytes, sum(stage.work.input_bytes for stage in actual.stages))
        self.assertLessEqual(len(actual.stages), source.MAX_STAGES)
        for stage in actual.stages:
            self.assertLessEqual(stage.work.input_bytes, source.MAX_INPUT_BYTES)
            self.assertLessEqual(stage.work.json_nodes, source.MAX_JSON_NODES)
        names = tuple(stage.name for stage in actual.stages)
        self.assertLess(names.index("receipt-derive"), names.index("absence-acquire"))
        self.assertLess(names.index("absence-admit"), names.index("transition-receipt"))
        self.assertEqual(sum(name.startswith("primary-write:") for name in names), 3)
        self.assertEqual(sum(name.startswith("index-fold:") for name in names), 12)
        manifest = json.loads(actual.original_manifest_bytes)
        self.assertEqual(manifest["originalCount"], len(pages))
        self.assertEqual(manifest["originalBytes"], actual.total_original_bytes)
        context = json.loads(actual.context_bytes)
        self.assertEqual(len(context["businessBeforeRoots"]), 4)
        self.assertEqual(len(context["authorizationBeforeRoots"]), 4)
        self.assertEqual(manifest["authorizationAfterRoots"], context["authorizationBeforeRoots"])
        self.assertEqual(actual.indexed_result.primary.authorization_after_roots,
            case["authorization_before_roots"])

    def test_raw_order_membership_and_independent_counted_head_cannot_be_substituted(self):
        for defect in ("order", "proof", "head"):
            case = connected_fixture()
            pages, _digest = originals(case)
            if defect == "order":
                pages["primary-chunk", 0] = pages["primary-chunk", source.rows.chunks.MAX_ROW_DATA_CHUNKS]
            elif defect == "proof":
                proof = source.frames.decode_proof(pages["primary-proof", 0], work=meter())
                proof["rootDigest"] = "sha256:" + "f" * 64
                pages["primary-proof", 0] = source.frames.encode_proof(proof, work=meter())
            else:
                first, *rest = case["counted_before_heads"]
                case["counted_before_heads"] = (replace(first, index_revision=first.index_revision + 1), *rest)
            visited = []
            with self.subTest(defect=defect), patch.object(source.time, "monotonic_ns", return_value=100):
                with self.assertRaises(ValueError):
                    replay(case, pages, check=lambda stage: visited.append(stage.name))
                expected = {"order": "row-decode:0", "proof": "row-admit-proof:0",
                    "head": "index-fold:" + case["counted_before_heads"][0].index_id}[defect]
                self.assertEqual(visited[-1], expected)

    def test_raw_callback_cannot_replace_reset_or_return_a_verdict(self):
        for defect in ("limits", "reset", "verdict"):
            case = connected_fixture()
            pages, _digest = originals(case)
            calls = []
            def read(kind, ordinal, work):
                calls.append((kind, ordinal))
                if defect == "limits": work.limits = QueryReadValidationLimits()
                elif defect == "reset": work.input_bytes = 0
                else: return {"verified": True}
                return pages[kind, ordinal]
            with self.subTest(defect=defect), patch.object(source.time, "monotonic_ns", return_value=100):
                with self.assertRaises(ValueError):
                    replay(case, pages, read=read)
                self.assertEqual(calls, [("primary-chunk", 0)])

    def test_sealed_meter_spending_and_continuity_verdict_are_refused(self):
        case = connected_fixture()
        pages, _digest = originals(case)
        held = []
        visited = []
        def check(stage):
            visited.append(stage.name)
            if stage.name == "capture" and not held:
                held.append(stage.work)
            elif stage.name == "row-open:0":
                held[0].charge(input_bytes=1)
        with patch.object(source.time, "monotonic_ns", return_value=100):
            with self.assertRaises(ValueError):
                replay(case, pages, check=check)
            self.assertEqual(visited[-1], "row-open:0")
            verdict_calls = []
            def verdict(stage):
                verdict_calls.append(stage.name)
                return True
            with self.assertRaises(ValueError):
                replay(case, pages, check=verdict)
            self.assertEqual(verdict_calls, ["capture"])

    def test_original_deadline_expiry_after_raw_callback_and_cancellation_do_not_close(self):
        case = connected_fixture()
        pages, _digest = originals(case)
        clock = [100]
        calls = []
        def read(kind, ordinal, work):
            calls.append((kind, ordinal))
            clock[0] = DEADLINE
            return pages[kind, ordinal]
        with patch.object(source.time, "monotonic_ns", side_effect=lambda: clock[0]):
            with self.assertRaises(ValueError):
                replay(case, pages, read=read)
        self.assertEqual(calls, [("primary-chunk", 0)])
        class Cancel(BaseException):
            pass
        cancellation = Cancel("synthetic original-reader cancellation")
        calls.clear()
        def cancel(kind, ordinal, work):
            calls.append((kind, ordinal))
            raise cancellation
        with patch.object(source.time, "monotonic_ns", return_value=100):
            with self.assertRaises(Cancel) as caught:
                replay(case, pages, read=cancel)
        self.assertIs(caught.exception, cancellation)
        self.assertEqual(calls, [("primary-chunk", 0)])

    def test_external_request_policy_and_head_aliases_are_not_adopted_after_capture(self):
        case = connected_fixture()
        pages, digest = originals(case)
        def read(kind, ordinal, work):
            case["request"]["arguments"]["approver_id"] = "changed caller alias"
            case["assertion_policy"]["origin"] = "https://changed.invalid"
            object.__setattr__(case["counted_before_heads"][0], "index_revision", 999)
            return pages[kind, ordinal]
        with patch.object(source.time, "monotonic_ns", return_value=100):
            actual = replay(case, pages, read=read)
        self.assertEqual(actual.transition.result["assertion_receipt_digest"], digest)
        self.assertNotIn(b"changed.invalid", actual.context_bytes)


if __name__ == "__main__":
    unittest.main()
