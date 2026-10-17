"""UNRUN synthetic raw replay controls with genuine ES256 and proof engines.

Independent primary/count-tree fixtures supply actual raw proofs. The source
projector is reused, so this is not an independent projection oracle. Building
a synthetic acquisition-format document is not a native acquisition, SQL/TLS,
current-root or authority claim. No crypto/proof guard is mocked.
"""
from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_jit_assertion_replay as replay
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_jit_assertion_planning import originals, configuration
from test_authority_radix_mutation import IndependentTree
from test_authority_radix_proof import sql_digest, sql_json
from test_authority_index_range import IndependentIndex


source = replay.source
REFUSALS = (ValueError, RuntimeError)


def meter(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def fixture():
    values, request, trees, business_json, authorization_json = originals()
    policy = configuration()["assertion_policy"]
    first_queries = source.receipt.queries(request["arguments"])
    first = tuple(trees[query.table].selected(query.absent_key) for query in first_queries)
    # This is real assertion verification on the synthetic fixture. Replay
    # independently verifies it again after genuine membership of these rows.
    context = source.core.KernelContext(source.OPERATION, request["arguments"], first,
        values["verified_at"], request["requestDigest"])
    row = source.receipt.receipt_from_context(context, assertion_policy=policy, work=meter())
    queries = (*first_queries, source.receipt.receipt_query(row["assertion_receipt_digest"]))
    by_query = tuple(trees[query.table].selected(query.absent_key) for query in queries)
    selected = tuple(sorted(by_query, key=lambda row: (row["table"], row["keyDigest"])))
    proofs = tuple(trees[row["table"]].proof(row) for row in by_query)
    records = tuple(source.reads._capture_query_read(source.OPERATION, query, resolved_query=query,
        ordered_selected_rows=(selected_row,), returned_row_count=int(selected_row["present"]), work=meter())
        for query, selected_row in zip(queries, by_query, strict=True))
    heads, raw_heads, frontiers = [], [], []
    for identity in source.heads._jit_receipt_ids():
        profile = replay.projection.profile_for(identity)
        leaves = []
        for business_row in trees[profile.table].rows.values():
            key = trees[profile.table].key(business_row)
            selected_row = trees[profile.table].selected(key)
            digest = sql_digest("catchplate.policyAuthorityAuthenticatedRow/v1",
                profile.table.encode("ascii"), sql_json(business_row))
            leaf = replay.projection.project_row(identity, business_row,
                primary_key_digest=selected_row["keyDigest"], primary_row_digest=digest)
            if leaf is not None:
                leaves.append(leaf)
        counted = IndependentIndex(leaves, profile=profile)
        heads.append(source.read_write.CompleteReadWriteHead(identity, 7, counted.root))
        raw_heads.append(dict(indexId=identity, indexRevision=7,
            rootDigest=counted.root.digest, leafCount=counted.root.count))
        frontiers.append(dict(indexId=identity, frontier=[dict(kind="leaf", key=leaf.key,
            primaryKeyDigest=leaf.primary_key_digest, primaryRowDigest=leaf.primary_row_digest)
            for leaf in sorted(leaves, key=lambda leaf: leaf.key)]))
    cutoff = values["verified_at"] - datetime(1970, 1, 1, tzinfo=timezone.utc)
    cutoff_us = (cutoff.days * 86400 + cutoff.seconds) * 1_000_000 + cutoff.microseconds
    raw = dict(schema=source.SCHEMA, sourceRevision=source.authority.SOURCE_REVISION,
        operation=source.OPERATION, operationManifestDigest=source.authority.OPERATION_MANIFEST_DIGEST,
        queryManifestDigest=source.primary_contract.source_query_manifest_digest(),
        authorizationManifestDigest=source.primary_contract.source_authorization_manifest_digest(),
        handlerContractDigest=source.authority.handler_contract_digest(source.OPERATION),
        request=request, assertionPolicy=policy, databaseCutoffUs=cutoff_us,
        businessBeforeRoots=business_json, authorizationBeforeRoots=authorization_json,
        countedBeforeHeads=raw_heads, selectedRows=selected, beforeProofs=proofs,
        queryReads=source._encode_reads(records, meter()), writeFrontiers=frontiers)
    expected = dict(request=request, assertion_policy=policy,
        business_before_roots=tuple(trees[item["table"]].root for item in business_json),
        authorization_before_roots=tuple(trees[item["table"]].root for item in authorization_json),
        counted_before_heads=tuple(heads), database_cutoff_us=cutoff_us)
    return encoded(raw), expected, trees, row


class JitAssertionReplayControls(unittest.TestCase):
    def test_actual_es256_memberships_inline_and_all_twelve_index_results(self):
        raw, expected, trees, receipt = fixture()
        original = copy.deepcopy(expected)
        work = meter()
        result = replay.replay_originals(raw, **expected, work=work)
        self.assertEqual(expected, original)
        self.assertEqual(len(result.queries), 8)
        self.assertEqual(result.queries[-1].absent_key,
            {"assertion_receipt_digest": receipt["assertion_receipt_digest"]})
        self.assertTrue(result.queries[-1].require_absence)
        self.assertEqual(len(result.query_reads), 8)
        self.assertEqual(len(result.mutations), 3)
        self.assertEqual(result.result["assertion_receipt_digest"], receipt["assertion_receipt_digest"])
        self.assertEqual(tuple(head.index_id for head in result.indexed_result.after_heads),
            source.heads._jit_receipt_ids())
        challenge = next(item["row"] for item in result.mutations if item["table"] == "webauthn_challenges")
        self.assertEqual(challenge["retention_reference_mask"], 2)
        self.assertEqual(challenge["retention_jit_receipt_digest"], receipt["assertion_receipt_digest"])
        for root in result.indexed_result.primary.business_after_roots:
            tree = trees[root.table]
            rows = list(copy.deepcopy(tree.rows).values())
            changes = [item for item in result.mutations if item["table"] == root.table]
            for mutation in changes:
                rows = [row for row in rows if tree.key(row) != mutation["key"]]
                if mutation["row"] is not None:
                    rows.append(mutation["row"])
            self.assertEqual(root, IndependentTree(rows, table=root.table, columns=tree.columns,
                revision=tree.root.root_revision + len(changes)).root)
        self.assertIsNotNone(result.metrics)
        self.assertEqual(result.metrics, work.metrics)

    def test_independent_policy_request_cutoff_and_complete_anchors_cannot_be_adopted(self):
        raw, expected, _trees, _receipt = fixture()
        for defect in ("policy", "request", "cutoff", "primary", "head", "head-bool", "head-order"):
            changed = copy.deepcopy(expected)
            if defect == "policy":
                changed["assertion_policy"]["origin"] = "https://different.invalid"
            elif defect == "request":
                changed["request"]["requestDigest"] = "sha256:" + "a" * 64
            elif defect == "cutoff":
                changed["database_cutoff_us"] += 1
            elif defect == "primary":
                changed["business_before_roots"] = changed["business_before_roots"][:-1]
            elif defect == "head":
                changed["counted_before_heads"] = changed["counted_before_heads"][:-1]
            elif defect == "head-bool":
                head = changed["counted_before_heads"][0]
                changed["counted_before_heads"] = (replace(head, index_revision=True), *changed["counted_before_heads"][1:])
            else:
                changed["counted_before_heads"] = tuple(reversed(changed["counted_before_heads"]))
            with self.subTest(defect=defect), self.assertRaises(REFUSALS):
                replay.replay_originals(raw, **changed, work=meter())

    def test_proof_row_query_record_and_counted_frontier_tampering_refuse(self):
        raw, expected, _trees, _receipt = fixture()
        for defect in ("primary-proof", "primary-row", "query-order", "query-value", "counted", "missing-index"):
            document = json.loads(raw)
            if defect == "primary-proof":
                document["beforeProofs"][0]["rootDigest"] = "sha256:" + "a" * 64
            elif defect == "primary-row":
                row = next(row for row in document["selectedRows"] if row["table"] == "approval_requests")
                row["row"]["status"] = "approved"
            elif defect == "query-order":
                document["queryReads"].reverse()
            elif defect == "query-value":
                document["queryReads"][-1]["returnedRowCount"] = 1
            elif defect == "counted":
                frontier = next(item["frontier"] for item in document["writeFrontiers"] if item["frontier"])
                frontier[0]["primaryRowDigest"] = "sha256:" + "a" * 64
            else:
                document["writeFrontiers"].pop()
            with self.subTest(defect=defect), self.assertRaises(REFUSALS):
                replay.replay_originals(encoded(document), **expected, work=meter())

    def test_valid_absence_at_another_receipt_key_cannot_replace_es256_derived_eighth(self):
        raw, expected, trees, _receipt = fixture()
        document = json.loads(raw)
        table = source.receipt.RECEIPT_TABLE
        changed = trees[table].selected({"assertion_receipt_digest": "sha256:" + "a" * 64})
        document["selectedRows"] = sorted((changed if row["table"] == table else row
            for row in document["selectedRows"]), key=lambda row: (row["table"], row["keyDigest"]))
        document["beforeProofs"] = [trees[table].proof(changed) if proof["table"] == table else proof
            for proof in document["beforeProofs"]]
        with self.assertRaises(REFUSALS):
            replay.replay_originals(encoded(document), **expected, work=meter())

    def test_changed_original_assertion_or_cutoff_needs_a_new_real_derived_receipt(self):
        raw, expected, _trees, _receipt = fixture()
        document = json.loads(raw)
        expected = copy.deepcopy(expected)
        # Both embedded and independent cutoff agree; the actual derived
        # receipt is now different, so old eighth-key evidence still refuses.
        expected["database_cutoff_us"] += 1_000_000
        document["databaseCutoffUs"] = expected["database_cutoff_us"]
        with self.assertRaises(REFUSALS):
            replay.replay_originals(encoded(document), **expected, work=meter())
        raw, expected, _trees, _receipt = fixture()
        document = json.loads(raw)
        request = copy.deepcopy(expected["request"])
        request["arguments"]["assertion"]["response"]["signature"] = "aW52YWxpZA"
        args = {key: value for key, value in request["arguments"].items() if key != "businessIntent"}
        request["arguments"]["businessIntent"] = source.authority.synthesize_business_intent(source.OPERATION, args)
        request["requestDigest"] = source.commitment._typed_request_digest(request, work=meter())
        request["operationId"] = source.commitment.operation_id(source.OPERATION, request["requestDigest"])
        expected["request"], document["request"] = request, request
        with self.assertRaises(REFUSALS):
            replay.replay_originals(encoded(document), **expected, work=meter())

    def test_canonical_originals_no_success_fields_and_original_work_ceiling(self):
        raw, expected, _trees, _receipt = fixture()
        for changed in (raw + b"\n", raw.replace(b'"schema":', b'"schema":"extra","schema":', 1),
                bytearray(raw), encoded({**json.loads(raw), "verified": True})):
            with self.assertRaises(REFUSALS):
                replay.replay_originals(changed, **expected, work=meter())
        work = meter(max_input_bytes=1024)
        limits = work.limits
        with self.assertRaises(REFUSALS):
            replay.replay_originals(raw, **expected, work=work)
        self.assertIs(work.limits, limits)
        self.assertLessEqual(work.input_bytes, 1024)


if __name__ == "__main__":
    unittest.main()
