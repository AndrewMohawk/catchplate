#!/usr/bin/env python3
"""UNRUN pure native-chunk controls, not a PostgreSQL or membership claim.

Fixtures encode flat rows with PostgreSQL-like JSON spacing and native UTF-8.
They exercise actual production reconstruction/meters. Full primary proofs,
native snapshots, aggregate JIT capacity and source transition admission remain
separate mandatory stages; no successful authority observation is fabricated.
"""
from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_jit_primary_chunks as source
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


QUERIES = (
    ("approval_requests", "approval", "id", "approval-one"),
    ("webauthn_challenges", "challenge", "id", "challenge-one"),
    ("webauthn_credentials", "credential", "id", "credential-one"),
    ("webauthn_trust_publication_high_water", "trust_high_water", "authority_scope", "webauthn-metadata"),
    ("webauthn_trust_publications", "trust_publication", "id", "publication-one"),
    ("rbac_role_bindings", "approver_role", "subject_id", "approver-one"),
    ("policy_high_water", "policy_high_water", "scope", "global"),
)


def meter(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def query(slot=0):
    table, name, column, value = QUERIES[slot]
    return source.core.BoundedQuery(query_id=source.core.query_program_id(source.OPERATION, name, table),
        table=table, predicates=(source.core.QueryPredicate(column, "eq", value),),
        order_by=(source.core.QueryOrder(column),), maximum_rows=1, absent_key={column: value})


def row(slot=0):
    table, _, column, value = QUERIES[slot]
    # This is a fixture generator, not an independent source-schema oracle.
    # The exact schema roster is independently checked in source review.
    result = {name: None if kind.endswith("?") else "text" if kind.startswith("s") else 0
        for name, kind in source._COLUMNS[table]}
    result[column] = value
    return result


def native(value):
    return json.dumps(value, ensure_ascii=False, separators=(", ", ": ")).encode("utf-8")


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def frames(raw):
    return [dict(total_bytes=len(raw), chunk_ordinal=ordinal, chunk_offset=offset,
        chunk_hex=raw[offset:offset + source.CHUNK_BYTES].hex())
        for ordinal, offset in enumerate(range(0, len(raw), source.CHUNK_BYTES))]


def reconstruct(value, slot=0, *, raw=None, work=None):
    work = meter() if work is None else work
    state = source.JitPrimaryRowChunks(query(slot), work=work)
    for record in frames(native(value) if raw is None else raw):
        state.accept([record], work=work)
    return state.finish(work=work), state, work


class JitPrimaryChunkControls(unittest.TestCase):
    def test_seven_fixed_queries_columns_and_native_scalar_reconstruction(self):
        self.assertEqual(tuple(len(source._COLUMNS[item[0]]) for item in QUERIES),
            (27, 17, 25, 9, 17, 10, 6))
        for slot, (table, _, column, value) in enumerate(QUERIES):
            with self.subTest(table=table):
                work = meter()
                sql, parameters = source.chunk_query(query(slot), ordinal=0, work=work)
                self.assertEqual(parameters, (value,))
                self.assertIn(f"FROM serverware_metadata.{table} AS target", sql)
                self.assertIn(f"WHERE target.{column} IS NOT DISTINCT FROM %s LIMIT 2", sql)
                self.assertIn("AS MATERIALIZED", sql)
                self.assertIn("pg_catalog.convert_to", sql)
                self.assertIn("pg_catalog.substring(body, 1, 131072)", sql)
                self.assertNotIn("wire_walk", sql)
                expected = row(slot)
                actual, state, work = reconstruct(expected, slot, work=work)
                self.assertEqual(actual, expected)
                self.assertEqual(state.native_bytes, len(native(expected)))
                self.assertEqual(state.data_chunks, 1)
                self.assertTrue(state.complete)
                self.assertIsNone(state.next_ordinal)
                self.assertGreater(work.input_bytes, state.native_bytes)

    def test_reassembles_split_utf8_before_decoding_and_owns_query(self):
        requested, expected = query(4), row(4)
        expected["bundle_json"] = ""
        prefix = native(expected).index(b'"bundle_json": "') + len(b'"bundle_json": "')
        expected["bundle_json"] = "x" * (source.CHUNK_BYTES - prefix - 1) + "\U0001f642" + "done"
        raw = native(expected)
        self.assertEqual(raw[source.CHUNK_BYTES - 1], 0xf0)
        with self.assertRaises(UnicodeDecodeError):
            raw[:source.CHUNK_BYTES].decode("utf-8")
        work = meter()
        state = source.JitPrimaryRowChunks(requested, work=work)
        requested.absent_key["id"] = "caller alias changed"
        object.__setattr__(requested, "table", "approval_requests")
        originals = frames(raw)
        for ordinal, record in enumerate(originals):
            self.assertEqual(state.next_ordinal, ordinal)
            held_query = state._next_query(work=work)
            self.assertEqual(held_query[1], ("publication-one",))
            self.assertEqual(held_query[2], "webauthn_trust_publications")
            self.assertEqual(held_query[4:], ("id", "publication-one", ordinal))
            state.accept([record], work=work)
            record["chunk_hex"] = "00"
        self.assertEqual(state.finish(work=work), expected)
        self.assertEqual(state.data_chunks, 2)

    def test_exact_row_transport_ceiling_and_unchanged_work_ceiling(self):
        expected = row(4)
        expected["bundle_json"] = ""
        amount = source.authority.MAX_PLAN_SELECTED_BYTES - len(canonical(expected))
        expected["bundle_json"] = "x" * amount
        raw = native(expected)
        self.assertEqual(len(canonical(expected)), source.authority.MAX_PLAN_SELECTED_BYTES)
        self.assertLessEqual(len(raw), source.MAX_ROW_NATIVE_BYTES)
        actual, state, work = reconstruct(expected, 4, raw=raw)
        self.assertEqual(actual, expected)
        self.assertEqual(state.data_chunks, 33)
        self.assertLessEqual(work.input_bytes, 64 * 1024 * 1024)
        # A row-only bound does not grant room for its enclosing selected
        # wrapper or other slots; the compound parent must still close those.
        bad = copy.deepcopy(expected)
        bad["bundle_json"] += "x"
        with self.assertRaises(ValueError):
            reconstruct(bad, 4)

    def test_absence_requires_initial_empty_observation_and_single_finish(self):
        work = meter()
        state = source.JitPrimaryRowChunks(query(), work=work)
        state.accept([], work=work)
        self.assertTrue(state.complete)
        self.assertEqual((state.native_bytes, state.data_chunks), (0, 0))
        self.assertIsNone(state.finish(work=work))
        with self.assertRaises(ValueError):
            state.finish(work=work)
        work = meter()
        state = source.JitPrimaryRowChunks(query(4), work=work)
        expected = row(4)
        expected["bundle_json"] = "x" * source.CHUNK_BYTES
        state.accept([frames(native(expected))[0]], work=work)
        with self.assertRaises(ValueError):
            state.accept([], work=work)
        with self.assertRaises(ValueError):
            state.finish(work=meter())

    def test_record_order_length_type_hex_and_budget_refusals_poison(self):
        expected = row(4)
        expected["bundle_json"] = "x" * source.CHUNK_BYTES
        initial = frames(native(expected))[0]
        for fault in ("extra", "bool-total", "large", "ordinal", "offset", "short", "upper", "null", "duplicate"):
            work = meter()
            state = source.JitPrimaryRowChunks(query(4), work=work)
            record = dict(initial)
            if fault == "extra": record["verdict"] = True
            elif fault == "bool-total": record["total_bytes"] = True
            elif fault == "large": record["total_bytes"] = source.MAX_ROW_NATIVE_BYTES + 1
            elif fault == "ordinal": record["chunk_ordinal"] = 1
            elif fault == "offset": record["chunk_offset"] = True
            elif fault == "short": record["chunk_hex"] = record["chunk_hex"][:-2]
            elif fault == "upper": record["chunk_hex"] = "FF" + record["chunk_hex"][2:]
            elif fault == "null": record["chunk_hex"] = None
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                state.accept([record, record] if fault == "duplicate" else [record], work=work)
            with self.assertRaises(ValueError):
                state.accept([initial], work=meter())
        work = meter()
        state = source.JitPrimaryRowChunks(query(4), work=work)
        before = state.native_bytes
        with self.assertRaises(ValueError):
            state.accept([initial], work=meter(max_input_bytes=64))
        self.assertEqual(state._native_bytes, before)

    def test_flat_parser_refuses_nested_duplicate_wrong_types_and_unicode(self):
        expected = row(6)
        original = native(expected)
        cases = (
            original.replace(b'"sequence": 0', b'"sequence": true'),
            original.replace(b'"sequence": 0', b'"sequence": 0.0'),
            original.replace(b'"sequence": 0', b'"sequence": -0'),
            original.replace(b'"sequence": 0', b'"sequence": 9223372036854775808'),
            original.replace(b'"sequence": 0', b'"sequence": ' + b'[' * 10000),
            original.replace(b'"scope": "global"', b'"scope": null'),
            original.replace(b'"scope": "global"', b'"scope": "other"'),
            original.replace(b'"scope": "global"', b'"scope": "global", "scope": "global"'),
            original.replace(b'"policy_id": "text"', b'"policy_id": "\\ud800"'),
            original.replace(b'"policy_id": "text"', b'"policy_id": "\\u0000"'),
            original.replace(b'"policy_id": "text"', b'"policy_id": "\xff"'),
        )
        for raw in cases:
            with self.subTest(prefix=raw[:100]), self.assertRaises(ValueError):
                reconstruct(expected, 6, raw=raw)
        credential = row(2)
        credential["sign_count"] = 1 << 31
        with self.assertRaises(ValueError):
            reconstruct(credential, 2)

    def test_closed_query_identity_ordinals_and_work_are_mandatory(self):
        requested = query()
        for changed in (replace(requested, query_id=requested.query_id + "-other"),
                replace(requested, require_absence=True), replace(requested, maximum_rows=2, absent_key=None),
                replace(requested, work_units=2), query(6)):
            if changed.table == "policy_high_water":
                changed.absent_key["scope"] = "caller-scope"
            with self.assertRaises((ValueError, RuntimeError)):
                source.chunk_query(changed, ordinal=0, work=meter())
        for ordinal in (True, -1, 33):
            with self.assertRaises(ValueError):
                source.chunk_query(query(), ordinal=ordinal, work=meter())
        with self.assertRaises(ValueError):
            source.JitPrimaryRowChunks(query(), work=object())
        state = source.JitPrimaryRowChunks(query(), work=meter())
        with self.assertRaises(ValueError):
            state.finish(work=meter())


if __name__ == "__main__":
    unittest.main()
