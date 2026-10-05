#!/usr/bin/env python3
"""Synthetic SQL rows with real independent radix proof reconstruction.

No PostgreSQL session, current-root admission, signed parent, transaction
continuity or live route is asserted. No proof verdict/guard is substituted.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_challenge_primary_reader as capture
from serverware import authority_challenge_retention as retention
from serverware import authority_index_reader as reader
from serverware import authority_index_trace as trace_shapes
from serverware import authority_query_read_work as measured
from serverware import authority_transition_core as core
from test_authority_radix_mutation import IndependentTree
from test_authority_radix_proof import sql_json, sql_digest

UUID = "00000000-0000-0000-0000-000000000001"
SHA = "sha256:" + "a" * 64


def challenge(identity=UUID, *, payload="{}"):
    row = dict(id=identity, challenge="synthetic-" + identity, challenge_type="registration",
        user_id="user", scope_key="scope", approval_request_id=None, payload_json=payload,
        created_at="2026-01-01T00:00:00+00:00", expires_at="2026-01-01T00:05:00+00:00",
        used_at=None)
    row.update({name: None for name in retention.DERIVED_FIELDS[:-1]})
    row["retention_reference_mask"] = 0
    return row


class Trace:
    operation = "webauthn.challenge.maintain"

    def __init__(self):
        self.records = []

    def read(self, table, key):
        if table == capture.TABLE:
            trace_shapes.validate_challenge_read_trace(self.operation, table, key)
        self.records.append((table, copy.deepcopy(key)))


class Cursor:
    """Literal bounded SELECT responder; never a database/proof authority."""

    def __init__(self, rows):
        self.rows = {row["id"]: copy.deepcopy(row) for row in rows}
        self.primary = IndependentTree(rows, table=capture.TABLE)
        self.leaves = {}
        for row in rows:
            selected = self.primary.selected({"id": row["id"]})
            proof = self.primary.proof(selected)
            tree_key = sql_digest("serverware.policyAuthorityAuthenticatedKey/v1",
                capture.TABLE.encode(), sql_json(selected["key"]))
            self.leaves[tree_key] = dict(key_json=sql_json(selected["key"]).decode(),
                row_digest=proof["rowDigest"], leaf_digest=proof["leafDigest"],
                root_revision=self.primary.root.root_revision)
        self.calls = []
        self.transform = lambda sql, rows: rows

    def execute(self, sql, parameters):
        self.calls.append((sql, parameters))
        if "FROM serverware_metadata.webauthn_challenges AS target" in sql:
            rows = [{"row_value": copy.deepcopy(self.rows[parameters[0]])}] if parameters[0] in self.rows else []
        elif "FROM serverware_metadata.policy_authority_authenticated_leaves" in sql:
            rows = [copy.deepcopy(self.leaves[parameters[1]])] if parameters[1] in self.leaves else []
        elif "FROM serverware_metadata.policy_authority_authenticated_tree_nodes" in sql:
            depth = parameters[1]
            rows = [dict(path_prefix=path, node_digest=self.primary.nodes[(depth, path)],
                         root_revision=self.primary.root.root_revision)
                    for path in parameters[2:-1] if (depth, path) in self.primary.nodes]
        else:
            raise AssertionError("unexpected SQL shape in synthetic challenge fixture")
        self.pending = self.transform(sql, rows)
        return self

    def fetchmany(self, maximum):
        return self.pending[:maximum]


class ChallengePrimaryReaderTests(unittest.TestCase):
    def context(self, rows=None, *, limits=None):
        cursor, trace = Cursor(rows if rows is not None else [challenge(), challenge(SHA)]), Trace()
        work = measured._ValidationWork(measured.QueryReadValidationLimits())
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work,
            limits=limits or reader._ReadAcquisitionLimits())
        return cursor, trace, work, acquisition

    def acquire(self, context, *, phase="expire", identity=UUID, root=None):
        cursor, trace, work, acquisition = context
        return capture.acquire_primary_original(cursor, phase=phase, primary_id=identity,
            primary_root=cursor.primary.root if root is None else root,
            trace=trace, work=work, acquisition=acquisition)

    def test_actual_original_and_independent_proof_match_for_all_source_phases(self):
        for phase in capture.PHASE_INDEX:
            for operation in ("webauthn.challenge.create", "webauthn.challenge.maintain"):
                with self.subTest(phase=phase, operation=operation):
                    context = self.context()
                    context[1].operation = operation
                    encoded = self.acquire(context, phase=phase, identity=SHA)
                    self.assertIs(type(encoded), bytes)
                    raw = json.loads(encoded)
                    selected = context[0].primary.selected({"id": SHA})
                    self.assertEqual(raw, dict(schema=capture.SCHEMA, selectedRows=[selected],
                        beforeProofs=[context[0].primary.proof(selected)]))
                    self.assertEqual(core.canonical_bytes(raw), encoded)
                    self.assertEqual(context[3].sql_reads, 66)
                    self.assertEqual(len(context[0].calls), len(context[1].records))
                    self.assertTrue(all("COUNT(" not in sql and "OFFSET" not in sql
                                        for sql, _ in context[0].calls))

    def test_missing_business_row_or_authenticated_leaf_is_not_absence_evidence(self):
        for table in ("webauthn_challenges AS target", "policy_authority_authenticated_leaves"):
            with self.subTest(table=table):
                context = self.context()
                context[0].transform = lambda sql, rows: [] if "FROM serverware_metadata." + table in sql else rows
                with self.assertRaises(reader.IndexReadError):
                    self.acquire(context)
                self.assertTrue(context[3].failed)

    def test_changed_full_row_or_real_stored_node_fails_genuine_membership(self):
        for target in ("row", "node"):
            with self.subTest(target=target):
                context = self.context()
                def change(sql, rows):
                    if rows and target == "row" and "webauthn_challenges AS target" in sql:
                        rows[0]["row_value"]["payload_json"] = '{"changed":true}'
                    if rows and target == "node" and "policy_authority_authenticated_tree_nodes" in sql:
                        rows[0]["node_digest"] = "sha256:" + "f" * 64
                    return rows
                context[0].transform = change
                with self.assertRaises(ValueError):
                    self.acquire(context)
                self.assertTrue(context[3].failed)

    def test_original_meter_and_exhausted_acquisition_cannot_be_replaced(self):
        context = self.context(limits=reader._ReadAcquisitionLimits(max_transport_bytes=100))
        with self.assertRaises(ValueError):
            self.acquire(context)
        self.assertTrue(context[3].failed)
        calls = len(context[0].calls)
        with self.assertRaises(ValueError):
            self.acquire(context)
        self.assertEqual(len(context[0].calls), calls)
        context = self.context()
        changed = (context[0], context[1], measured._ValidationWork(measured.QueryReadValidationLimits()), context[3])
        with self.assertRaises(ValueError):
            self.acquire(changed)
        self.assertEqual(context[0].calls, [])

    def test_one_maximum_canonical_row_fits_unchanged_component_budgets(self):
        row = challenge(payload="")
        row["payload_json"] = "x" * (reader.MAX_PRIMARY_ROW_BYTES - len(core.canonical_bytes(row)))
        self.assertEqual(len(core.canonical_bytes(row)), 1024 * 1024)
        context = self.context([row])
        encoded = self.acquire(context)
        self.assertEqual(json.loads(encoded)["selectedRows"][0]["row"], row)
        self.assertLess(len(encoded), capture.MAX_RAW_BYTES)
        self.assertLessEqual(context[3].transport_bytes, 4 * 1024 * 1024)
        self.assertLessEqual(context[2].input_bytes, 64 * 1024 * 1024)
        self.assertLessEqual(context[2].json_nodes, 1000000)

    def test_non_source_context_and_unclosed_or_non_scalar_rows_are_refused(self):
        for change in ("phase", "id", "operation", "extra", "nested", "boolean-mask"):
            with self.subTest(change=change):
                context = self.context()
                if change == "operation":
                    context[1].operation = "webauthn.challenge.consume"
                if change in {"extra", "nested", "boolean-mask"}:
                    def alter(sql, rows):
                        if rows and "webauthn_challenges AS target" in sql:
                            key = "unexpected" if change == "extra" else "payload_json" if change == "nested" else "retention_reference_mask"
                            rows[0]["row_value"][key] = False if change == "boolean-mask" else {}
                        return rows
                    context[0].transform = alter
                with self.assertRaises(ValueError):
                    self.acquire(context, phase="unknown" if change == "phase" else "expire",
                        identity="custom-id" if change == "id" else UUID)
                self.assertTrue(context[3].failed)


if __name__ == "__main__":
    unittest.main()
