#!/usr/bin/env python3
"""UNRUN raw native pages plus independent primary trees, not native custody.

Rows have the source flat schema, but arbitrary non-key scalars intentionally
make no valid WebAuthn receipt claim. Actual memberships/query records/order and
compound component bounds are exercised; ES256 and the eighth read are later.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_jit_primary_rows as source
from catchplate.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
from test_authority_jit_assertion_planning import originals
from test_authority_jit_primary_chunks import row as source_row, frames, native
from test_authority_radix_mutation import IndependentTree


def meter(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def fixture(*, large=None, absent=()):
    _values, request, _old, _business, _authorization = originals()
    queries = source.source.receipt.queries(request["arguments"])
    rows = {}
    for ordinal, query in enumerate(queries):
        value = source_row(ordinal)
        value.update(query.absent_key)
        if large and query.table in large:
            field, size = large[query.table]
            value[field] = "x" * size
        rows[query.table] = [] if query.table in absent else [value]
    rows[source.source.receipt.RECEIPT_TABLE] = []
    contracts = source.source.primary_contract.primary_table_contracts(source.source.OPERATION)
    trees = {contract.table: IndependentTree(rows[contract.table], table=contract.table,
        columns=contract.key_columns) for contract in contracts}
    roots = tuple(source.primary_reader.primary.PrimaryRoot(table, trees[table].root.root_revision,
        trees[table].root.root_digest, trees[table].root.leaf_count) for table in sorted(trees))
    classes = {item.table: item.root_class for item in contracts}
    owner = source._JitPrimaryRows(request=request,
        business_before_roots=tuple(root for root in roots if classes[root.table] == "business"),
        authorization_before_roots=tuple(root for root in roots if classes[root.table] == "authorization"),
        database_cutoff_us=1_700_000_000_000_000, work=meter())
    return owner, request, roots, trees, queries


def consume(owner, query, tree, *, physical=False):
    codec = owner.begin_row(meter())
    selected = tree.selected(query.absent_key)
    pages = frames(native(selected["row"])) if selected["present"] else [None]
    for page in pages:
        work = meter()
        values = [] if page is None else [page]
        if physical:
            # Only tests the same actual codec join. This does not pretend a
            # SQL collector ran; the physical-reader controls own that proof.
            with owner._acquisition_binding(kind="chunk", work=work) as held:
                if held is not codec:
                    raise AssertionError("source codec replaced")
                held.accept(values, work=work)
            owner.observe_acquired_chunk(work)
        else:
            owner.consume_chunk(values, work)
    actual = owner.decode_row(meter())
    if actual != selected:
        raise AssertionError("native reconstructed original differs from independent tree")
    owner.admit_proof(tree.proof(selected), meter())


class JitPrimaryRowsControls(unittest.TestCase):
    def test_seven_actual_memberships_and_query_records_before_receipt(self):
        owner, request, roots, trees, queries = fixture(absent=("rbac_role_bindings",))
        for ordinal, query in enumerate(queries):
            self.assertEqual(owner.next_stage, ("row-open", ordinal))
            consume(owner, query, trees[query.table], physical=bool(ordinal % 2))
        self.assertEqual(owner.next_stage, ("finish", 7))
        result = owner.finish(meter())
        self.assertEqual(result.request, request)
        self.assertEqual(tuple(sorted((*result.business_before_roots, *result.authorization_before_roots),
            key=lambda item: item.table)), roots)
        self.assertEqual((len(result.business_before_roots), len(result.authorization_before_roots)), (4, 4))
        self.assertEqual(len(result.context.selected_rows), 7)
        self.assertEqual(len(result.context.query_reads), 7)
        self.assertEqual(len(result.before_proofs), 7)
        self.assertEqual(result.data_chunks, 6)
        self.assertNotIn(source.source.receipt.RECEIPT_TABLE,
            {selected["table"] for selected in result.context.selected_rows})
        for record, query in zip(result.context.query_reads, queries):
            self.assertEqual(record.query_id, query.query_id)
        with self.assertRaises(ValueError):
            owner.finish(meter())

    def test_large_trust_row_is_chunked_then_genuinely_proved(self):
        owner, _, _, trees, queries = fixture(large={"webauthn_trust_publications":
            ("bundle_json", 2 * 1024 * 1024)})
        for query in queries:
            consume(owner, query, trees[query.table])
        result = owner.finish(meter())
        self.assertGreater(result.native_bytes, 2 * 1024 * 1024)
        self.assertLessEqual(result.data_chunks, source.chunks.MAX_TOTAL_DATA_CHUNKS)
        trust = next(item for item in result.context.selected_rows
            if item["table"] == "webauthn_trust_publications")
        self.assertEqual(len(trust["row"]["bundle_json"]), 2 * 1024 * 1024)

    def test_independent_root_classes_are_exact_and_cannot_be_relabelled(self):
        owner, request, roots, _trees, _queries = fixture()
        business, authorization = owner._business, owner._authorization
        for wrong_business, wrong_authorization in ((roots, ()),
                (authorization, business),
                ((authorization[0], *business[1:]), (business[0], *authorization[1:]))):
            with self.subTest(tables=tuple(root.table for root in wrong_business)), self.assertRaises(ValueError):
                source._JitPrimaryRows(request=request, business_before_roots=wrong_business,
                    authorization_before_roots=wrong_authorization,
                    database_cutoff_us=1_700_000_000_000_000, work=meter())

    def test_bad_proof_or_changed_exposed_original_never_advances(self):
        for defect in ("proof", "row"):
            owner, _, _, trees, queries = fixture()
            query, tree = queries[0], trees[queries[0].table]
            selected = tree.selected(query.absent_key)
            owner.begin_row(meter())
            for page in frames(native(selected["row"])):
                owner.consume_chunk([page], meter())
            exposed = owner.decode_row(meter())
            proof = tree.proof(selected)
            if defect == "proof": proof["rowDigest"] = "sha256:" + "f" * 64
            else: exposed["row"]["status"] = "substituted"
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                owner.admit_proof(proof, meter())
            self.assertEqual(owner._slot, 0)
            with self.assertRaises(ValueError):
                owner.begin_row(meter())

    def test_capture_detaches_request_and_full_root_originals(self):
        owner, request, roots, trees, queries = fixture()
        request["arguments"]["approval_request_id"] = "caller mutation"
        object.__setattr__(roots[0], "root_revision", 12345)
        for query in queries:
            consume(owner, query, trees[query.table])
        result = owner.finish(meter())
        self.assertNotEqual(result.request["arguments"]["approval_request_id"], "caller mutation")
        self.assertNotEqual(result.business_before_roots[0].root_revision, 12345)

    def test_aggregate_selected_bound_is_not_seven_fresh_row_allowances(self):
        owner, _, _, trees, queries = fixture(large={
            "approval_requests": ("canonical_request", 2 * 1024 * 1024),
            "webauthn_challenges": ("payload_json", 2 * 1024 * 1024)})
        consume(owner, queries[0], trees[queries[0].table])
        query = queries[1]
        owner.begin_row(meter())
        selected = trees[query.table].selected(query.absent_key)
        with self.assertRaises(ValueError):
            for page in frames(native(selected["row"])):
                owner.consume_chunk([page], meter())
            owner.decode_row(meter())
        self.assertEqual(owner._slot, 1)

    def test_fixed_order_same_codec_and_actual_work_are_required(self):
        owner, _, _, trees, queries = fixture()
        codec = owner.begin_row(meter())
        with self.assertRaises(ValueError):
            owner.begin_row(meter())
        owner, _, _, _, _ = fixture()
        original_work = owner._meters[0][0]
        with self.assertRaises(ValueError):
            owner.begin_row(original_work)
        owner, _, _, _, _ = fixture()
        codec = owner.begin_row(meter())
        with self.assertRaises(ValueError):
            owner.observe_acquired_chunk(meter())
        owner, _, _, trees, queries = fixture()
        codec = owner.begin_row(meter())
        selected = trees[queries[0].table].selected(queries[0].absent_key)
        owner.consume_chunk([frames(native(selected["row"]))[0]], meter())
        with self.assertRaises(ValueError):
            owner.decode_row(meter(max_input_bytes=1))
        self.assertTrue(owner._failed)

    def test_source_binding_requires_immediate_chunk_ack_and_distinct_proof_admission(self):
        owner, _, _, trees, queries = fixture()
        query, tree = queries[0], trees[queries[0].table]
        selected = tree.selected(query.absent_key)
        codec = owner.begin_row(meter())
        work = meter()
        with owner._acquisition_binding(kind="chunk", work=work) as actual:
            self.assertIs(actual, codec)
            actual.accept([frames(native(selected["row"]))[0]], work=work)
        self.assertIs(owner._pending_chunk_work, work)
        owner.observe_acquired_chunk(work)
        exposed = owner.decode_row(meter())
        acquisition_work = meter()
        with owner._acquisition_binding(kind="proof", work=acquisition_work) as actual:
            self.assertIs(actual[0], exposed)
            self.assertEqual(actual[1], tree.root)
            self.assertTrue(owner._busy)
        self.assertEqual(owner.next_stage, ("row-proof", 0))
        with self.assertRaises(ValueError):
            owner.admit_proof(tree.proof(selected), acquisition_work)
        self.assertTrue(owner._failed)

    def test_native_binding_reentry_anchor_mutation_or_unacknowledged_progress_poison(self):
        for defect in ("reentry", "root", "query", "no-ack"):
            owner, _, _, trees, queries = fixture()
            selected = trees[queries[0].table].selected(queries[0].absent_key)
            owner.begin_row(meter())
            work = meter()
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                with owner._acquisition_binding(kind="chunk", work=work) as codec:
                    if defect == "reentry":
                        owner.consume_chunk([], meter())
                    elif defect == "root":
                        object.__setattr__(owner._roots[0], "root_revision", True)
                    elif defect == "query":
                        owner._queries[1].absent_key["id"] = "substituted"
                    else:
                        codec.accept([frames(native(selected["row"]))[0]], work=work)
                if defect == "no-ack":
                    owner.decode_row(meter())
            self.assertTrue(owner._failed)


if __name__ == "__main__":
    unittest.main()
