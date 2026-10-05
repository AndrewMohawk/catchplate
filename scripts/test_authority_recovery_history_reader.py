#!/usr/bin/env python3
"""Synthetic stored-row SQL with real independent counted/primary trees.

These controls exercise actual acquisition and proof reconstruction, not a
PostgreSQL transaction, current-root admission, compound owner or live route.
No successful proof result or verifier guard is substituted.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_index_projection as projection
from serverware import authority_index_reader as acquisition_reader
from serverware import authority_index_trace as index_trace
from serverware import authority_recovery_history_reader as history
from serverware import authority_query_read_work as measured
from serverware import authority_transition_core as core
from serverware.authority_index_heads import CapturedIndexHead
from test_authority_index_join import expected_profile, expected_leaf, expected_interval
from test_authority_index_range import IndependentIndex
from test_authority_radix_mutation import IndependentTree
from test_authority_radix_proof import sql_json, sql_digest


def credential(identity, user="target", *, label="hardware", revoked=None):
    return dict(id=identity, credential_id="wire-" + identity, user_id=user, label=label,
        public_key_cose="synthetic-cose", sign_count=1, aaguid=None,
        authenticator_class="unknown", attestation_fmt=None, attestation_trusted=0,
        attestation_trust_path="[]", attestation_leaf_sha256=None, attestation_root_sha256=None,
        attestation_trust_bundle_digest=None, attestation_trust_bundle_sequence=None,
        attestation_verified_at=None, transports="[]", dev_private_key_pem=None,
        created_at="2026-01-01T00:00:00+00:00", updated_at="2026-01-01T00:00:00+00:00",
        last_used_at=None, revoked_at=revoked, revoked_by=None, revocation_reason=None,
        revocation_source=None)


class Trace:
    operation = "webauthn.recovery.create"

    def __init__(self):
        self.records = []
        self.callback = None

    def read(self, table, key):
        if table in (acquisition_reader.LEAF_TABLE, acquisition_reader.NODE_TABLE, history.TABLE):
            index_trace.validate_recovery_history_read_trace(self.operation, table, key)
        self.records.append((table, copy.deepcopy(key)))
        if self.callback is not None:
            self.callback()


class Cursor:
    """Literal synthetic SELECT responder, never a database/proof authority."""

    def __init__(self, rows):
        self.rows = {row["id"]: copy.deepcopy(row) for row in rows}
        self.primary = IndependentTree(rows, table=history.TABLE)
        profile = expected_profile(history.INDEX_ID)
        leaves = []
        self.leaf_rows = []
        self.primary_leaves = {}
        for row in rows:
            selected = self.primary.selected({"id": row["id"]})
            proof = self.primary.proof(selected)
            leaf = expected_leaf(profile, row, selected, proof)
            leaves.append(leaf)
            self.leaf_rows.append(dict(index_id=history.INDEX_ID, projection_digest=profile.projection_digest,
                index_key=leaf.key, primary_id=row["id"], primary_key_digest=leaf.primary_key_digest,
                primary_row_digest=leaf.primary_row_digest, index_revision=7))
            tree_key = sql_digest("serverware.policyAuthorityAuthenticatedKey/v1", history.TABLE.encode(),
                                  sql_json(selected["key"]))
            self.primary_leaves[tree_key] = dict(key_json=sql_json(selected["key"]).decode(),
                row_digest=proof["rowDigest"], leaf_digest=proof["leafDigest"],
                root_revision=self.primary.root.root_revision)
        self.counted = IndependentIndex(leaves, profile=profile)
        self.counted_nodes = {(len(prefix), prefix): dict(index_id=history.INDEX_ID,
            projection_digest=profile.projection_digest, depth=len(prefix), path_prefix=prefix,
            node_digest=value[0], subtree_count=value[1], index_revision=7)
            for prefix, value in self.counted.nodes.items() if prefix and value[1]}
        self.calls = []
        self.transform = lambda sql, rows: rows

    def execute(self, sql, parameters):
        self.calls.append((sql, parameters))
        if '"policy_authority_counted_index_leaves"' in sql:
            upper = parameters[2] if len(parameters) == 4 else None
            rows = sorted((copy.deepcopy(r) for r in self.leaf_rows
                if r["index_key"] >= parameters[1] and (upper is None or r["index_key"] < upper)),
                key=lambda r: r["index_key"])[:parameters[-1]]
        elif '"policy_authority_counted_index_nodes"' in sql:
            identities = tuple(zip(parameters[:-2:2], parameters[1:-2:2]))
            rows = [copy.deepcopy(self.counted_nodes[k]) for k in identities if k in self.counted_nodes]
        elif "FROM serverware_metadata.webauthn_credentials AS target" in sql:
            rows = [{"row_value": copy.deepcopy(self.rows[parameters[0]])}] if parameters[0] in self.rows else []
        elif "FROM serverware_metadata.policy_authority_authenticated_leaves" in sql:
            rows = [copy.deepcopy(self.primary_leaves[parameters[1]])] if parameters[1] in self.primary_leaves else []
        elif "FROM serverware_metadata.policy_authority_authenticated_tree_nodes" in sql:
            depth = parameters[1]
            rows = [dict(path_prefix=path, node_digest=self.primary.nodes[(depth, path)],
                         root_revision=self.primary.root.root_revision)
                    for path in parameters[2:-1] if (depth, path) in self.primary.nodes]
        else:
            raise AssertionError("synthetic fixture received an unexpected SQL shape")
        self.pending = self.transform(sql, rows)
        return self

    def fetchmany(self, maximum):
        return self.pending[:maximum]


class RecoveryHistoryReaderTests(unittest.TestCase):
    def context(self, rows=None, *, limits=None):
        if rows is None:
            rows = [credential("a"), credential("b", revoked="2026-01-02T00:00:00+00:00"),
                    credential("c", user="other")]
        cursor, trace = Cursor(rows), Trace()
        work = measured._ValidationWork(measured.QueryReadValidationLimits())
        acquisition = acquisition_reader._ReadAcquisitionBudget(cursor, trace, work=work,
            limits=limits or acquisition_reader._ReadAcquisitionLimits())
        head = CapturedIndexHead(history.INDEX_ID, history.TABLE, projection.COUNTED_PROFILE,
            cursor.counted.profile.projection_digest, projection.projection_manifest_digest(), 7, cursor.counted.root)
        return cursor, trace, work, acquisition, head

    def count(self, context):
        cursor, trace, work, acquisition, head = context
        return history.acquire_history_count(cursor, operation=trace.operation, user_id="target", head=head,
            trace=trace, work=work, acquisition=acquisition)

    def page(self, context, *, ordinal=0, count=2, lower=None):
        cursor, trace, work, acquisition, head = context
        interval = expected_interval(cursor.counted.profile, {"user_id": "target"})
        return history.acquire_history_page(cursor, operation=trace.operation, user_id="target", head=head,
            primary_root=cursor.primary.root, ordinal=ordinal, authenticated_count=count,
            lower=interval.lower if lower is None else lower, trace=trace, work=work, acquisition=acquisition)

    def test_real_raw_count_and_contiguous_pages_include_revoked_history(self):
        count_context = self.context()
        count_bytes = self.count(count_context)
        self.assertIs(type(count_bytes), bytes)
        raw_count = json.loads(count_bytes)
        self.assertEqual(core.canonical_bytes(raw_count), count_bytes)
        self.assertEqual(set(raw_count), {"schema", "frontier"})
        self.assertEqual(raw_count["schema"], history.COUNT_SCHEMA)
        self.assertTrue(all(item["kind"] == "opaque" for item in raw_count["frontier"]))
        first_context = self.context()
        first_bytes = self.page(first_context)
        self.assertIs(type(first_bytes), bytes)
        first = json.loads(first_bytes)
        second_context = self.context()
        second_bytes = self.page(second_context, ordinal=1, lower=first["upper"])
        self.assertIs(type(second_bytes), bytes)
        second = json.loads(second_bytes)
        self.assertEqual(core.canonical_bytes(first), first_bytes)
        self.assertEqual(core.canonical_bytes(second), second_bytes)
        self.assertEqual(first["upper"], second["lower"])
        self.assertEqual(second["upper"], expected_interval(first_context[0].counted.profile,
                                                          {"user_id": "target"}).upper)
        self.assertEqual({page["selectedRows"][0]["row"]["id"] for page in (first, second)}, {"a", "b"})
        for page, context in ((first, first_context), (second, second_context)):
            self.assertEqual(set(page), {"schema", "ordinal", "lower", "upper", "selectedRows", "beforeProofs", "frontier"})
            self.assertEqual(page["beforeProofs"], [context[0].primary.proof(page["selectedRows"][0])])
            self.assertEqual(len(page["selectedRows"]), 1)
            self.assertEqual(context[3].sql_reads, len(context[0].calls))
            self.assertEqual(len(context[1].records), len(context[0].calls))
            self.assertTrue(all("COUNT(" not in sql and "OFFSET" not in sql for sql, _ in context[0].calls))
            self.assertLessEqual(context[3].transport_bytes, 4 * 1024 * 1024)
            self.assertLessEqual(context[2].input_bytes, 64 * 1024 * 1024)

    def test_skipped_candidate_cannot_substitute_for_complete_range(self):
        context = self.context()
        cursor = context[0]
        interval = expected_interval(cursor.counted.profile, {"user_id": "target"})
        inside = sorted((r for r in cursor.leaf_rows if interval.lower <= r["index_key"] < interval.upper),
                        key=lambda r: r["index_key"])
        cursor.transform = lambda sql, rows: [copy.deepcopy(inside[1])] if '"policy_authority_counted_index_leaves"' in sql else rows
        with self.assertRaises(acquisition_reader.IndexReadError):
            self.page(context)
        self.assertTrue(context[3].failed)

    def test_tampered_full_row_and_actual_primary_node_are_rejected(self):
        for target in ("row", "node"):
            with self.subTest(target=target):
                context = self.context()
                def corrupt(sql, rows):
                    if target == "row" and "FROM serverware_metadata.webauthn_credentials AS target" in sql and rows:
                        rows[0]["row_value"]["label"] = "tampered"
                    if target == "node" and "FROM serverware_metadata.policy_authority_authenticated_tree_nodes" in sql and rows:
                        rows[0]["node_digest"] = "sha256:" + "f" * 64
                    return rows
                context[0].transform = corrupt
                with self.assertRaises(ValueError):
                    self.page(context)
                self.assertTrue(context[3].failed)

    def test_original_context_and_cumulative_budget_cannot_be_replaced_or_reset(self):
        context = self.context(limits=acquisition_reader._ReadAcquisitionLimits(max_transport_bytes=100))
        with self.assertRaises(ValueError):
            self.count(context)
        self.assertTrue(context[3].failed)
        before = len(context[0].calls)
        with self.assertRaises(ValueError):
            self.count(context)
        self.assertEqual(len(context[0].calls), before)
        context = self.context()
        changed = (*context[:2], measured._ValidationWork(measured.QueryReadValidationLimits()), *context[3:])
        with self.assertRaises(ValueError):
            self.page(changed)
        self.assertEqual(context[0].calls, [])

    def test_one_maximum_canonical_row_fits_original_phase_budgets(self):
        row = credential("max", label="")
        row["label"] = "x" * (acquisition_reader.MAX_PRIMARY_ROW_BYTES - len(core.canonical_bytes(row)))
        self.assertEqual(len(core.canonical_bytes(row)), 1024 * 1024)
        context = self.context([row])
        encoded = self.page(context, count=1)
        self.assertIs(type(encoded), bytes)
        self.assertLess(len(encoded), history.MAX_RAW_BYTES)
        raw = json.loads(encoded)
        self.assertEqual(core.canonical_bytes(raw), encoded)
        self.assertEqual(raw["selectedRows"][0]["row"], row)
        self.assertLessEqual(context[2].input_bytes, 64 * 1024 * 1024)
        self.assertLessEqual(context[2].json_nodes, 1000000)

    def test_nested_row_and_non_source_ordinals_are_refused(self):
        for change in ("nested", "extra", "boolean-count"):
            with self.subTest(change=change):
                context = self.context()
                if change != "boolean-count":
                    def alter(sql, rows):
                        if "FROM serverware_metadata.webauthn_credentials AS target" in sql and rows:
                            rows[0]["row_value"]["label" if change == "nested" else "unexpected"] = {}
                        return rows
                    context[0].transform = alter
                with self.assertRaises(ValueError):
                    self.page(context, count=True if change == "boolean-count" else 2)
                self.assertTrue(context[3].failed)


if __name__ == "__main__":
    unittest.main()
