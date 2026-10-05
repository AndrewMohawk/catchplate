#!/usr/bin/env python3
"""UNRUN acquisition component controls, not native database acceptance.

These exercise real request commitments, counted-head physical accounting and
raw sparse-frontier encoding with independent primary/count-tree fixtures.
The head cursor is explicitly synthetic; source-order checks are not execution
of the full acquired snapshot or proof-reader path. No authority is issued.
"""
from __future__ import annotations

import ast
import copy
from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_recovery_invalidation_acquisition as source
from test_authority_recovery_invalidation import fixture, meter

proof = source.proof


def request_for(call):
    arguments = copy.deepcopy(call["context"]["arguments"])
    values = {name: value for name, value in arguments.items() if name != "businessIntent"}
    arguments["businessIntent"] = proof.contract.synthesize_business_intent(source.OPERATION, values)
    request = dict(schema="serverware.policyAuthorityV9Request/v1", operation=source.OPERATION,
        operationId="sha256:" + "0" * 64, requestDigest="sha256:" + "0" * 64,
        handler=proof.contract.operation_spec(source.OPERATION)["handler"],
        operationManifestDigest=proof.contract.OPERATION_MANIFEST_DIGEST, arguments=arguments)
    request["requestDigest"] = source.commitment._typed_request_digest(request, work=meter())
    request["operationId"] = source.commitment.operation_id(source.OPERATION, request["requestDigest"])
    return request


def head_rows(call):
    rows = []
    for value in call["context"]["countedBeforeHeads"]:
        profile = proof.projection.profile_for(value["indexId"])
        rows.append(dict(index_id=value["indexId"], table_name=profile.table,
            counted_profile=proof.heads.counted.PROFILE, projection_digest=profile.projection_digest,
            projection_manifest_digest=proof.projection.projection_manifest_digest(),
            index_revision=value["indexRevision"], root_digest=value["rootDigest"],
            leaf_count=value["leafCount"]))
    return rows


class HeadTrace:
    """Synthetic head-only component trace, never a native PlannerTrace."""

    operation = source.OPERATION

    def __init__(self):
        self.entries = []

    def read(self, table, key):
        if table != proof.heads.HEAD_TABLE:
            raise AssertionError("head fixture saw another table")
        proof.heads.validate_head_trace_key(self.operation, key, include_write_heads=True)
        self.entries.append((table, copy.deepcopy(key)))


class HeadCursor:
    def __init__(self, rows):
        self.rows = copy.deepcopy(rows)
        self.calls = []

    def execute(self, sql, parameters):
        if "FROM serverware_metadata.policy_authority_counted_index_heads" not in sql:
            raise AssertionError("head fixture saw another physical query")
        self.calls.append((sql, parameters))
        return self

    def fetchmany(self, maximum):
        return copy.deepcopy(self.rows[:maximum])


def capture_heads(call, *, expected=None, work=None):
    cursor, trace = HeadCursor(head_rows(call)), HeadTrace()
    work = work or meter()
    acquisition = source.reader._ReadAcquisitionBudget(cursor, trace, work=work)
    expected = tuple(call["context"]["countedBeforeHeads"]) if expected is None else expected
    with acquisition.read_phase(cursor, trace, work):
        captured = source._heads(cursor, expected=expected, trace=trace, work=work, acquisition=acquisition)
    return captured, cursor, trace, work, acquisition


class RecoveryInvalidationAcquisitionControls(unittest.TestCase):
    def test_true_typed_request_commitments_not_just_digest_shapes(self):
        request = request_for(fixture())
        source._request(request, meter())
        for name in ("requestDigest", "operationId", "operationManifestDigest", "handler"):
            changed = copy.deepcopy(request)
            changed[name] = "sha256:" + "f" * 64 if name != "handler" else "different"
            with self.subTest(field=name), self.assertRaises((ValueError, RuntimeError)):
                source._request(changed, meter())
        changed = copy.deepcopy(request)
        changed["arguments"]["recovery_id"] += "-different"
        with self.assertRaises((ValueError, RuntimeError)):
            source._request(changed, meter())

    def test_root_documents_remain_exact_and_detached(self):
        call = fixture()
        documents = tuple(copy.deepcopy(call["context"]["businessBeforeRoots"]))
        roots = source._root_objects(documents, meter())
        self.assertEqual(tuple(root.json_projection() for root in roots), documents)
        documents[0]["rootRevision"] += 1
        self.assertNotEqual(roots[0].root_revision, documents[0]["rootRevision"])
        documents[0]["leafCount"] = True
        with self.assertRaises(ValueError):
            source._root_objects(documents, meter())

    def test_all_nine_actual_head_rows_spend_one_original_physical_ledger(self):
        call = fixture()
        captured, cursor, trace, work, acquisition = capture_heads(call)
        self.assertEqual(tuple(head.index_id for head in captured), proof.heads._recovery_write_ids(source.OPERATION))
        self.assertEqual(len(cursor.calls), 1)
        self.assertEqual(acquisition.sql_reads, 1)
        self.assertEqual(acquisition.returned_rows, 9)
        self.assertGreater(acquisition.parameter_bytes, 0)
        self.assertGreater(acquisition.transport_bytes, 0)
        self.assertGreater(work.hash_work, 0)
        self.assertEqual(len(trace.entries), 1)
        acquisition.require_idle(cursor, trace, work)

    def test_missing_or_changed_counted_predecessor_cannot_be_adopted(self):
        call = fixture()
        expected = tuple(copy.deepcopy(call["context"]["countedBeforeHeads"]))
        expected[0]["indexRevision"] += 1
        with self.assertRaises(ValueError):
            capture_heads(call, expected=expected)
        with self.assertRaises(ValueError):
            capture_heads(call, expected=expected[:-1])
        cursor, trace, work = HeadCursor(head_rows(call)[:-1]), HeadTrace(), meter()
        acquisition = source.reader._ReadAcquisitionBudget(cursor, trace, work=work)
        with self.assertRaises(ValueError):
            with acquisition.read_phase(cursor, trace, work):
                source._heads(cursor, expected=tuple(call["context"]["countedBeforeHeads"]),
                    trace=trace, work=work, acquisition=acquisition)
        self.assertTrue(acquisition.failed)

    def test_raw_frontiers_round_trip_through_actual_invalidation_proof(self):
        call = fixture()
        captured, *_ = capture_heads(call)
        ids = proof.heads._recovery_write_ids(source.OPERATION)
        before = {row["indexId"]: row for row in call["context"]["countedBeforeHeads"]}
        inputs = proof._index_inputs(list(call["index_inputs"]), ids, before, meter())
        raw_inputs = source._frontier_originals(inputs, expected_ids=ids, captured=captured, work=meter())
        self.assertEqual(raw_inputs, call["index_inputs"])
        raw = proof.produce_originals(**{**call, "index_inputs": raw_inputs}, work=meter())
        actual = proof.replay_originals(raw, expected_context=call["context"], work=meter())
        self.assertTrue(actual.affected)
        self.assertEqual(len(actual.write.after_heads), 9)
        with self.assertRaises(ValueError):
            source._frontier_originals(inputs[:-1], expected_ids=ids, captured=captured, work=meter())
        changed = (replace(inputs[0], index_revision=inputs[0].index_revision + 1), *inputs[1:])
        with self.assertRaises(ValueError):
            source._frontier_originals(changed, expected_ids=ids, captured=captured, work=meter())

    def test_exhausted_original_allowance_fails_without_sql_or_replacement(self):
        call = fixture()
        cursor, trace, work = HeadCursor(head_rows(call)), HeadTrace(), meter(max_input_bytes=16)
        limits = work.limits
        acquisition = source.reader._ReadAcquisitionBudget(cursor, trace, work=work)
        with self.assertRaises(ValueError):
            with acquisition.read_phase(cursor, trace, work):
                source._heads(cursor, expected=tuple(call["context"]["countedBeforeHeads"]),
                    trace=trace, work=work, acquisition=acquisition)
        self.assertIs(work.limits, limits)
        self.assertEqual(cursor.calls, [])
        self.assertTrue(acquisition.failed)

    def test_source_sequencing_retains_target_first_and_no_unmetered_sql(self):
        text = Path(source.__file__).read_text()
        module = ast.parse(text)
        owner = next(node for node in module.body if isinstance(node, ast.FunctionDef)
            and node.name == "acquire_originals")
        calls = [node for node in ast.walk(owner) if isinstance(node, ast.Call)]
        named = [(node.lineno, node.func.attr) for node in calls if isinstance(node.func, ast.Attribute)]
        self.assertFalse(any(name in ("execute", "fetchall", "fetchmany", "_derive_multiproofs",
            "_ValidationWork", "_ReadAcquisitionBudget") for _, name in named))
        follow = next(line for line, name in named if name == "followup_queries")
        first = next(line for line, name in named if name == "target_query")
        produce = next(line for line, name in named if name == "produce_originals")
        self.assertLess(first, follow)
        self.assertLess(follow, produce)
        self.assertEqual(sum(name == "read_phase" for _, name in named), 1)
        self.assertIn("physical.acquire_exact_primary", text)


if __name__ == "__main__":
    unittest.main()
