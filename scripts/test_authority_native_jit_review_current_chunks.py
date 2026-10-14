#!/usr/bin/env python3
"""Pure codec controls: no PostgreSQL, authority, snapshot or admission claim.

Rows use PostgreSQL-like spacing and UTF-8. The fixture creates independent
meters for hypothetical source-fixed chunk/decode stages; it does not prove
the real reader's stage ownership, aggregate budget or membership schedule.
Originals are opaque printable text here: their semantic and cryptographic
validation belongs to the retained-pair/trust owners, not this transport.
"""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_native_jit_review_current_chunks as source
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


QUERIES = (
    ("session", "oidc_browser_sessions", "id", "session-one"),
    ("credential", "webauthn_credentials", "id", "credential-one"),
    ("trust_high_water", "webauthn_trust_publication_high_water", "authority_scope", "webauthn-metadata"),
    ("trust_publication", "webauthn_trust_publications", "id", "publication-one"),
    ("rbac_authority", "rbac_authority_state", "authority_id", 1),
    ("reviewer_role", "rbac_role_bindings", "subject_id", "reviewer-one"),
    ("policy_high_water", "policy_high_water", "scope", "global"),
    ("approval", "approval_requests", "id", "approval-one"),
    ("retained_pair", "policy_authority_native_jit_review_pairs", "approval_request_id", "approval-one"),
    ("receipt", "approval_review_receipts", "id", "receipt-one"),
    ("receipt_capacity", "policy_authority_bounded_aggregate_states", "aggregate_id", "receipt-capacity-one"),
    ("audit", "metadata_audit_outbox", "id", "audit-one"),
    ("audit_capacity", "policy_authority_bounded_aggregate_states", "aggregate_id", "audit-capacity-one"),
)


def meter(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def query(slot=0, operation=source.RECEIPT_OPERATION):
    name, table, column, value = QUERIES[slot]
    return source.core.BoundedQuery(query_id=source.core.query_program_id(operation, name, table),
        table=table, predicates=(source.core.QueryPredicate(column, "eq", value),),
        order_by=(source.core.QueryOrder(column),), maximum_rows=1, absent_key={column: value})


def row(slot=0):
    _, table, column, value = QUERIES[slot]
    # Generator, not an independent schema oracle. Exact source columns and
    # types require separate source review against the effective PostgreSQL DDL.
    result = {name: None if kind.endswith("?") else "text" if kind.startswith("s") else 0
        for name, kind in source._COLUMNS[table]}
    result[column] = value
    return result


def native(value):
    return json.dumps(value, ensure_ascii=False, separators=(", ", ": ")).encode("utf-8")


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def frames(raw):
    for ordinal, offset in enumerate(range(0, len(raw), source.CHUNK_BYTES)):
        yield dict(total_bytes=len(raw), chunk_ordinal=ordinal, chunk_offset=offset,
            chunk_hex=raw[offset:offset + source.CHUNK_BYTES].hex())


def reconstruct(expected, slot=0, *, raw=None, operation=source.RECEIPT_OPERATION):
    state = source.NativeJitReviewRowChunks(operation, query(slot, operation), work=meter())
    for record in frames(native(expected) if raw is None else raw):
        state.accept([record], work=meter())
    work = meter()
    actual = state.finish(work=work)
    return actual, state, work


class NativeJitReviewCurrentChunkControls(unittest.TestCase):
    def test_closed_nine_and_thirteen_slot_full_rows_and_fixed_sql(self):
        self.assertEqual(tuple(len(source._COLUMNS[item[1]]) for item in QUERIES),
            (18, 25, 9, 17, 6, 10, 6, 27, 20, 7, 17, 15, 17))
        for operation, count in ((source.AUTHORIZE_OPERATION, 9), (source.RECEIPT_OPERATION, 13)):
            for slot, (_, table, column, value) in enumerate(QUERIES[:count]):
                with self.subTest(operation=operation, table=table, slot=slot):
                    sql, params = source.chunk_query(operation, query(slot, operation), ordinal=0, work=meter())
                    self.assertEqual(params, (value,))
                    self.assertIs(type(params[0]), int if slot == 4 else str)
                    self.assertIn(f"FROM serverware_metadata.{table} AS target", sql)
                    self.assertIn(f"WHERE target.{column} IS NOT DISTINCT FROM %s LIMIT 2", sql)
                    self.assertIn("AS MATERIALIZED", sql)
                    self.assertIn("pg_catalog.to_jsonb(target)", sql)
                    self.assertIn("pg_catalog.substring(body, 1, 131072)", sql)
                    self.assertNotIn("EXECUTE", sql)
                    expected = row(slot)
                    actual, state, _ = reconstruct(expected, slot, operation=operation)
                    self.assertEqual(actual, expected)
                    self.assertEqual(state.canonical_bytes, len(canonical(expected)))
                    self.assertEqual(state.native_bytes, len(native(expected)))
                    self.assertEqual(state.data_chunks, 1)
                    self.assertTrue(state.complete)
                    self.assertIsNone(state.next_ordinal)

    def test_operation_slot_key_and_query_forms_are_exact(self):
        for operation in ("jit.assertion.issue", "jit.review-receipt.issue", "", True):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                source.NativeJitReviewRowChunks(operation, query(), work=meter())
        for slot in range(9, 13):
            with self.subTest(slot=slot), self.assertRaises(ValueError):
                source.NativeJitReviewRowChunks(source.AUTHORIZE_OPERATION,
                    query(slot, source.AUTHORIZE_OPERATION), work=meter())
        requested = query()
        changed_queries = (
            ("query-id", lambda: replace(requested, query_id=requested.query_id + "-other")),
            ("table", lambda: replace(requested, table="oidc_browser_sessions; SELECT 1")),
            ("maximum-rows", lambda: replace(requested, maximum_rows=2, absent_key=None)),
            ("require-absence", lambda: replace(requested, require_absence=True)),
            ("work-units", lambda: replace(requested, work_units=2)),
            ("proof-primitive", lambda: replace(requested, proof_primitive="secondary-index")),
            ("predicate", lambda: replace(requested,
                predicates=(source.core.QueryPredicate("id", "ne", "session-one"),))),
            ("ordering", lambda: replace(requested,
                order_by=(source.core.QueryOrder("id", descending=True),))),
        )
        for label, make_query in changed_queries:
            with self.subTest(query=label), self.assertRaises((ValueError, RuntimeError)):
                changed = make_query()
                source.NativeJitReviewRowChunks(source.RECEIPT_OPERATION, changed, work=meter())
        for slot, value in ((4, True), (4, "1"), (4, 2), (2, "global"), (6, "tenant"),
                (0, " session-one"), (0, "session\x00one"), (0, "x" * 1025)):
            changed = query(slot)
            column = QUERIES[slot][2]
            with self.subTest(slot=slot, value=value), self.assertRaises((ValueError, RuntimeError)):
                changed = replace(changed, absent_key={column: value},
                    predicates=(source.core.QueryPredicate(column, "eq", value),))
                source.NativeJitReviewRowChunks(source.RECEIPT_OPERATION, changed, work=meter())

    def test_query_and_frames_are_detached_and_split_utf8_is_reassembled(self):
        requested, expected = query(1), row(1)
        expected["label"] = ""
        prefix = native(expected).index(b'"label": "') + len(b'"label": "')
        expected["label"] = "x" * (source.CHUNK_BYTES - prefix - 1) + "\U0001f642" + "done"
        raw = native(expected)
        self.assertEqual(raw[source.CHUNK_BYTES - 1], 0xf0)
        state = source.NativeJitReviewRowChunks(source.RECEIPT_OPERATION, requested, work=meter())
        requested.absent_key["id"] = "caller changed"
        object.__setattr__(requested, "table", "approval_requests")
        for ordinal, record in enumerate(frames(raw)):
            selected = state._next_query(work=meter())
            self.assertEqual(selected[1], ("credential-one",))
            self.assertEqual(selected[2], "webauthn_credentials")
            self.assertEqual(selected[4:], ("id", "credential-one", ordinal))
            state.accept([record], work=meter())
            record["chunk_hex"] = "00"
        self.assertEqual(state.finish(work=meter()), expected)
        self.assertEqual(state.data_chunks, 2)

    def test_absence_is_only_initial_and_finish_is_one_use(self):
        state = source.NativeJitReviewRowChunks(source.RECEIPT_OPERATION, query(9), work=meter())
        state.accept([], work=meter())
        self.assertIsNone(state.finish(work=meter()))
        self.assertEqual((state.native_bytes, state.data_chunks, state.canonical_bytes), (0, 0, 4))
        with self.assertRaises(ValueError):
            state.finish(work=meter())
        state = source.NativeJitReviewRowChunks(source.RECEIPT_OPERATION, query(3), work=meter())
        expected = row(3)
        expected["bundle_json"] = "x" * source.CHUNK_BYTES
        state.accept([next(frames(native(expected)))], work=meter())
        with self.assertRaises(ValueError):
            state.accept([], work=meter())
        with self.assertRaises(ValueError):
            state.finish(work=meter())

    def test_frame_types_order_lengths_hex_and_totals_refuse_and_poison(self):
        expected = row(3)
        expected["bundle_json"] = "x" * source.CHUNK_BYTES
        first, second = list(frames(native(expected)))
        for fault in ("extra", "bool-total", "large", "ordinal", "offset", "short", "upper", "null", "duplicate"):
            state = source.NativeJitReviewRowChunks(source.RECEIPT_OPERATION, query(3), work=meter())
            record = dict(first)
            if fault == "extra": record["verified"] = True
            elif fault == "bool-total": record["total_bytes"] = True
            elif fault == "large": record["total_bytes"] = state._query.native_cap + 1
            elif fault == "ordinal": record["chunk_ordinal"] = 1
            elif fault == "offset": record["chunk_offset"] = False
            elif fault == "short": record["chunk_hex"] = record["chunk_hex"][:-2]
            elif fault == "upper": record["chunk_hex"] = "FF" + record["chunk_hex"][2:]
            elif fault == "null": record["chunk_hex"] = None
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                state.accept([record, record] if fault == "duplicate" else [record], work=meter())
            with self.assertRaises(ValueError):
                state.accept([first], work=meter())
        state = source.NativeJitReviewRowChunks(source.RECEIPT_OPERATION, query(3), work=meter())
        state.accept([first], work=meter())
        second["total_bytes"] -= 1
        second["chunk_hex"] = second["chunk_hex"][:-2]
        with self.assertRaises(ValueError):
            state.accept([second], work=meter())

    def test_flat_schema_types_integer_ranges_and_unicode_refuse(self):
        expected = row(4)
        raw = native(expected)
        cases = (
            raw.replace(b'"authority_id": 1', b'"authority_id": true'),
            raw.replace(b'"authority_id": 1', b'"authority_id": "1"'),
            raw.replace(b'"authority_id": 1', b'"authority_id": 2'),
            raw.replace(b'"generation": 0', b'"generation": 0.0'),
            raw.replace(b'"generation": 0', b'"generation": -0'),
            raw.replace(b'"generation": 0', b'"generation": 01'),
            raw.replace(b'"generation": 0', b'"generation": 9223372036854775808'),
            raw.replace(b'"generation": 0', b'"generation": ' + b'[' * 1000),
            raw.replace(b'"generation": 0', b'"generation": null'),
            raw.replace(b'"state_digest": "text"', b'"state_digest": "\\ud800"'),
            raw.replace(b'"state_digest": "text"', b'"state_digest": "\\u0000"'),
            raw.replace(b'"state_digest": "text"', b'"state_digest": "\xff"'),
            raw.replace(b'"state_digest": "text"', b'"state_digest": "text", "state_digest": "text"'),
            raw.replace(b'"updated_at": "text"', b'"unexpected": "text"'),
        )
        for changed in cases:
            with self.subTest(raw=changed[:90]), self.assertRaises(ValueError):
                reconstruct(expected, 4, raw=changed)
        credential = row(1)
        credential["sign_count"] = 1 << 31
        with self.assertRaises(ValueError):
            reconstruct(credential, 1)
        credential["sign_count"] = -(1 << 31)
        self.assertEqual(reconstruct(credential, 1)[0], credential)

    def test_each_opaque_original_has_its_own_printable_ascii_limit(self):
        for slot in (3, 8):
            for name, limit in source._ORIGINAL_LIMITS[QUERIES[slot][1]].items():
                for value in ("x" * (limit + 1), "x", "éé", "x\n", "x\x7f"):
                    expected = row(slot)
                    expected[name] = value
                    with self.subTest(slot=slot, name=name, size=len(value)), self.assertRaises(ValueError):
                        reconstruct(expected, slot)

    def test_largest_escaped_pair_and_trust_rows_fit_unchanged_decode_meter(self):
        for slot in (8, 3):
            expected = row(slot)
            for name, limit in source._ORIGINAL_LIMITS[QUERIES[slot][1]].items():
                expected[name] = "\\" * limit
            actual, state, work = reconstruct(expected, slot)
            self.assertEqual(actual, expected)
            canonical_size = len(canonical(expected))
            self.assertEqual(state.canonical_bytes, canonical_size)
            self.assertGreater(state.native_bytes, 4 * 1024 * 1024)
            self.assertLessEqual(state.canonical_bytes, source._ROW_MAX_CANONICAL_BYTES[QUERIES[slot][1]])
            self.assertLessEqual(work.input_bytes, 3 * canonical_size + 16 * 1024)
            self.assertEqual(work.limits.max_input_bytes, 64 * 1024 * 1024)

    def test_small_row_canonical_ceiling_is_exact(self):
        expected = row(1)
        expected["label"] = ""
        cap = source._ROW_MAX_CANONICAL_BYTES["webauthn_credentials"]
        expected["label"] = "x" * (cap - len(canonical(expected)))
        actual, state, _ = reconstruct(expected, 1)
        self.assertEqual(actual, expected)
        self.assertEqual(state.canonical_bytes, cap)
        expected["label"] += "x"
        with self.assertRaises(ValueError):
            reconstruct(expected, 1)

    def test_work_and_ordinal_failures_cannot_be_restarted(self):
        for ordinal in (True, -1, 9):
            with self.subTest(ordinal=ordinal), self.assertRaises(ValueError):
                source.chunk_query(source.RECEIPT_OPERATION, query(), ordinal=ordinal, work=meter())
        with self.assertRaises(ValueError):
            source.NativeJitReviewRowChunks(source.RECEIPT_OPERATION, query(), work=object())
        state = source.NativeJitReviewRowChunks(source.RECEIPT_OPERATION, query(), work=meter())
        initial = next(frames(native(row())))
        with self.assertRaises(ValueError):
            state.accept([initial], work=meter(max_input_bytes=32))
        self.assertEqual(state._native_bytes, 0)
        with self.assertRaises(ValueError):
            state.accept([initial], work=meter())
        state = source.NativeJitReviewRowChunks(source.RECEIPT_OPERATION, query(), work=meter())
        state.accept([initial], work=meter())
        with self.assertRaises(ValueError):
            state.finish(work=meter(max_input_bytes=32))
        with self.assertRaises(ValueError):
            state.finish(work=meter())


if __name__ == "__main__":
    unittest.main()
