#!/usr/bin/env python3
"""UNRUN same-call receipt/absence controls with actual synthetic ES256.

Independent trees and reconstructed flat native row frames exercise genuine
membership and receipt semantics. No SQL, current-root, native custody or
compound-clock acceptance is claimed. Padding is source-shaped test data, not
a claim that every legacy producer emits these rows.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_jit_receipt_absence as source
from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
from test_authority_jit_assertion_planning import originals, configuration
from test_authority_jit_primary_chunks import row as flat_row, frames, native
from test_authority_radix_mutation import IndependentTree


def meter(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def fixture(*, almost_full=False):
    values, request, originals_by_table, _, _ = originals()
    queries = source.source.receipt.queries(request["arguments"])
    rows = {}
    for slot, query in enumerate(queries):
        selected = originals_by_table[query.table].selected(query.absent_key)
        if selected["present"]:
            padded = flat_row(slot)
            padded.update(selected["row"])
            rows[query.table] = [padded]
        else:
            rows[query.table] = []
    rows[source.source.receipt.RECEIPT_TABLE] = []
    contracts = source.source.primary_contract.primary_table_contracts(source.source.OPERATION)

    def build_trees():
        return {item.table: IndependentTree(rows[item.table], table=item.table, columns=item.key_columns)
            for item in contracts}

    trees = build_trees()
    if almost_full:
        rows["approval_requests"][0]["decision_note"] = ""
        trees = build_trees()
        selected = tuple(trees[query.table].selected(query.absent_key) for query in queries)
        remaining = source.source.authority.MAX_REQUEST_BYTES - len(source.core.canonical_bytes(selected)) - 1
        rows["approval_requests"][0]["decision_note"] = "x" * remaining
        trees = build_trees()
    roots = tuple(source.primary_reader.primary.PrimaryRoot(item.table,
        trees[item.table].root.root_revision, trees[item.table].root.root_digest,
        trees[item.table].root.leaf_count) for item in contracts)
    delta = values["verified_at"] - source.primary_rows._EPOCH
    cutoff = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    classes = {item.table: item.root_class for item in contracts}
    row_owner = source.primary_rows._JitPrimaryRows(request=request,
        business_before_roots=tuple(root for root in roots if classes[root.table] == "business"),
        authorization_before_roots=tuple(root for root in roots if classes[root.table] == "authorization"),
        database_cutoff_us=cutoff, work=meter())
    for query in queries:
        selected = trees[query.table].selected(query.absent_key)
        row_owner.begin_row(meter())
        pages = frames(native(selected["row"])) if selected["present"] else [None]
        for page in pages:
            row_owner.consume_chunk([] if page is None else [page], meter())
        actual = row_owner.decode_row(meter())
        if actual != selected:
            raise AssertionError("source row reconstruction differs from independent tree")
        row_owner.admit_proof(trees[query.table].proof(selected), meter())
    captured = row_owner.finish(meter())
    receipt_owner = source.semantics._JitAssertionReceipt(captured.context,
        assertion_policy=configuration()["assertion_policy"], work=meter())
    receipt_owner.actor_policy(meter())
    receipt_owner.receipt(meter())
    return row_owner, receipt_owner, trees


def lookup(owner, trees):
    query, root = owner.query_inputs()
    tree = trees[query.table]
    selected = tree.selected(query.absent_key)
    return query, root, selected, tree.proof(selected)


class JitReceiptAbsenceControls(unittest.TestCase):
    def test_capture_reserves_before_closed_owner_roster_walks(self):
        rows, receipt, _ = fixture()
        with patch.object(source, "_closed_sources", side_effect=AssertionError("reservation must precede roster")):
            with self.assertRaises(ValueError):
                source._JitReceiptAbsence(rows=rows, receipt_owner=receipt, work=meter(max_input_bytes=1))

    def test_genuine_receipt_selects_eighth_absence_and_full_context(self):
        rows, receipt, trees = fixture()
        works = [meter() for _ in source.STAGES]
        owner = source._JitReceiptAbsence(rows=rows, receipt_owner=receipt, work=works[0])
        query, root, selected, proof = lookup(owner, trees)
        self.assertEqual(query.absent_key,
            {"assertion_receipt_digest": receipt._receipt["assertion_receipt_digest"]})
        self.assertTrue(query.require_absence)
        self.assertEqual(root.table, source.source.receipt.RECEIPT_TABLE)
        owner.admit(selected_row=selected, before_proof=proof, work=works[1])
        selected["key"]["assertion_receipt_digest"] = "caller alias changed"
        proof["rootDigest"] = "caller alias changed"
        result = owner.finish(works[2])
        self.assertEqual(len(result.context.selected_rows), 8)
        self.assertEqual(len(result.context.query_reads), 8)
        self.assertEqual(len(result.before_proofs), 8)
        self.assertEqual(len(result.business_before_roots), 4)
        self.assertEqual(len(result.authorization_before_roots), 4)
        self.assertEqual(result.context.database_now, receipt._context.database_now)
        self.assertEqual(result.context.request_digest, rows._request["requestDigest"])
        self.assertEqual(tuple(item.query_id for item in result.context.query_reads),
            tuple(item.query_id for item in result.queries))
        absent = next(item for item in result.context.selected_rows if item["table"] == query.table)
        self.assertFalse(absent["present"])
        self.assertEqual(absent["key"], query.absent_key)
        self.assertTrue(owner._closed)
        with self.assertRaises(ValueError):
            owner.query_inputs()

    def test_unclosed_or_failed_original_owner_cannot_select_a_key(self):
        for defect in ("rows-open", "receipt-open", "receipt-failed", "receipt-dto"):
            rows, receipt, _ = fixture()
            if defect == "rows-open": rows._closed = False
            elif defect == "receipt-open": receipt._closed = False
            elif defect == "receipt-failed": receipt._failed = True
            else: receipt = copy.deepcopy(receipt._receipt)
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                source._JitReceiptAbsence(rows=rows, receipt_owner=receipt, work=meter())

    def test_seven_row_context_and_original_cutoff_must_join(self):
        for defect in ("row", "arguments", "cutoff", "query-record"):
            rows, receipt, _ = fixture()
            if defect == "row":
                receipt._context.selected_rows[0]["row"]["decision_note"] = "changed"
            elif defect == "arguments":
                receipt._context.arguments["approver_id"] = "different-actor"
            elif defect == "cutoff":
                # Keep identity joins genuine while making the closed row
                # owner's exact cutoff differ from the ES256 input cutoff.
                from datetime import timedelta
                rows._now += timedelta(microseconds=1)
            else:
                record = receipt._context.query_reads[0]
                object.__setattr__(record, "returned_row_count", 0)
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                source._JitReceiptAbsence(rows=rows, receipt_owner=receipt, work=meter())

    def test_wrong_key_presence_or_proof_is_terminal(self):
        for defect in ("key", "present", "proof"):
            rows, receipt, trees = fixture()
            owner = source._JitReceiptAbsence(rows=rows, receipt_owner=receipt, work=meter())
            query, _, selected, proof = lookup(owner, trees)
            if defect == "key":
                selected = trees[query.table].selected({"assertion_receipt_digest": "sha256:" + "f" * 64})
                proof = trees[query.table].proof(selected)
            elif defect == "present":
                selected["present"], selected["row"] = True, dict(receipt._receipt)
            else:
                proof["rootDigest"] = "sha256:" + "f" * 64
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                owner.admit(selected_row=selected, before_proof=proof, work=meter())
            self.assertTrue(owner._failed)
            with self.assertRaises(ValueError):
                owner.finish(meter())

    def test_exposed_query_and_root_stay_bound_until_admission(self):
        for defect in ("key", "query", "root"):
            rows, receipt, trees = fixture()
            owner = source._JitReceiptAbsence(rows=rows, receipt_owner=receipt, work=meter())
            query, root, selected, proof = lookup(owner, trees)
            if defect == "key": query.absent_key["assertion_receipt_digest"] = "sha256:" + "f" * 64
            elif defect == "query": object.__setattr__(query, "require_absence", False)
            else: object.__setattr__(root, "root_revision", root.root_revision + 1)
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                owner.admit(selected_row=selected, before_proof=proof, work=meter())

    def test_stage_order_original_work_and_cancellation_are_terminal(self):
        for defect in ("skip", "reuse", "upstream-reuse", "reset", "limits", "cancel", "budget"):
            rows, receipt, trees = fixture()
            first = meter()
            owner = source._JitReceiptAbsence(rows=rows, receipt_owner=receipt, work=first)
            _, _, selected, proof = lookup(owner, trees)
            class Cancel(BaseException):
                pass
            if defect == "reset": receipt._meters[0][0].input_bytes = 0
            elif defect == "limits": first.limits = QueryReadValidationLimits()
            with self.subTest(defect=defect), self.assertRaises((ValueError, Cancel)):
                if defect == "skip": owner.finish(meter())
                elif defect == "cancel":
                    with patch.object(source.primary_reader, "_membership", side_effect=Cancel()):
                        owner.admit(selected_row=selected, before_proof=proof, work=meter())
                else:
                    work = (first if defect == "reuse" else rows._meters[0][0]
                        if defect == "upstream-reuse" else meter(max_input_bytes=1)
                        if defect == "budget" else meter())
                    owner.admit(selected_row=selected, before_proof=proof, work=work)
            self.assertTrue(owner._failed)

    def test_eighth_business_row_cannot_borrow_framework_capacity(self):
        rows, receipt, trees = fixture(almost_full=True)
        owner = source._JitReceiptAbsence(rows=rows, receipt_owner=receipt, work=meter())
        _, _, selected, proof = lookup(owner, trees)
        owner.admit(selected_row=selected, before_proof=proof, work=meter())
        with self.assertRaises(ValueError):
            owner.finish(meter())
        self.assertTrue(owner._failed)


if __name__ == "__main__":
    unittest.main()
