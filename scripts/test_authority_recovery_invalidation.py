#!/usr/bin/env python3
"""UNRUN draft controls: real component proofs, not witness/DB admission.

Primary and counted tree hashes use independent fixture engines. Projection
uses the actual source projector; these controls are not an independent
projection oracle. No authority, key, browser or database is provisioned.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_recovery_invalidation as proof
from catchplate import authority_query_read_work as measured
from test_authority_recovery_terminal import (
    NOW, REQUEST, arguments, ceremony, revocation, challenge, aggregate_row,
)
from test_authority_radix_mutation import IndependentTree
from test_authority_radix_proof import sql_digest, sql_json
from test_authority_index_range import IndependentIndex

CHALLENGE = "00000000-0000-0000-0000-000000000001"
REFUSALS = (ValueError, proof.core.TransitionKernelError)


def meter(**limits):
    return measured._ValidationWork(measured.QueryReadValidationLimits(**limits))


def fixture(*, kind="replacement-registration", status="prepared", absent=False):
    terminal = proof.terminal
    table = terminal.CEREMONIES if kind == "replacement-registration" else terminal.REVOCATIONS
    target = (ceremony(challenge_id=CHALLENGE) if table == terminal.CEREMONIES else revocation())
    target["status"] = status
    args = dict(arguments(), ceremony_type=kind)
    active = not absent and status in (terminal.LIVE if table == terminal.CEREMONIES else ("prepared",))
    values = {table: [] if absent else [target]}
    keys = [(table, {"id": args["recovery_id"]})]
    if active and table == terminal.CEREMONIES:
        joined = dict(challenge(target), id=CHALLENGE)
        values[terminal.retention.CHALLENGE_TABLE] = [joined]
        keys.append((terminal.retention.CHALLENGE_TABLE, {"id": CHALLENGE}))
    if active:
        values[terminal.capacity.OUTBOX_TABLE] = []
        values[terminal.capacity.AGGREGATE_TABLE] = [aggregate_row(live=0)]
        keys.extend(((terminal.capacity.OUTBOX_TABLE, {"id": "webauthn-recovery-burned:" + args["recovery_id"]}),
            (terminal.capacity.AGGREGATE_TABLE, {"aggregate_id": terminal.capacity.AGGREGATE_ID})))
    trees, business, authorization = {}, [], []
    for contract in terminal.contracts.primary_table_contracts(proof.OPERATION):
        tree = IndependentTree(values.get(contract.table, []), table=contract.table,
            columns=contract.key_columns, revision=7)
        trees[contract.table] = tree
        (business if contract.root_class == "business" else authorization).append(tree.root)
    selected = tuple(trees[table].selected(key) for table, key in keys)
    before = tuple(trees[row["table"]].proof(row) for row in selected)
    challenge_rows = values.get(terminal.retention.CHALLENGE_TABLE, [])
    heads, inputs = [], []
    for identity in proof.heads._recovery_write_ids(proof.OPERATION):
        profile = proof.projection.profile_for(identity)
        leaves = []
        for row in challenge_rows:
            selected_challenge = trees[terminal.retention.CHALLENGE_TABLE].selected({"id": row["id"]})
            row_digest = sql_digest("catchplate.policyAuthorityAuthenticatedRow/v1",
                terminal.retention.CHALLENGE_TABLE.encode(), sql_json(row))
            leaf = proof.projection.project_row(identity, row,
                primary_key_digest=selected_challenge["keyDigest"], primary_row_digest=row_digest)
            if leaf is not None:
                leaves.append(leaf)
        counted = IndependentIndex(leaves, profile=profile)
        heads.append(proof.read_write.CompleteReadWriteHead(identity, 7, counted.root))
        if active and table == terminal.CEREMONIES:
            inputs.append(dict(indexId=identity, indexRevision=7,
                rootDigest=counted.root.digest, leafCount=counted.root.count,
                frontier=[dict(kind="leaf", key=leaf.key, primaryKeyDigest=leaf.primary_key_digest,
                    primaryRowDigest=leaf.primary_row_digest) for leaf in sorted(leaves, key=lambda leaf: leaf.key)]))
    context = proof.context_document(arguments=args, request_digest=REQUEST, database_now=NOW,
        business_before_roots=tuple(business), authorization_before_roots=tuple(authorization),
        counted_before_heads=tuple(heads), terminal_retention_seconds=86_400, maximum_retained=100, work=meter())
    return dict(context=context, selected_rows=selected, before_proofs=before, index_inputs=tuple(inputs))


class RecoveryInvalidationControls(unittest.TestCase):
    def test_two_active_branches_use_genuine_raw_replay_and_complete_write_heads(self):
        for kind in ("replacement-registration", "lost-active-key-decommission"):
            call = fixture(kind=kind)
            original = copy.deepcopy(call)
            raw = proof.produce_originals(**call, work=meter())
            result = proof.replay_originals(raw, expected_context=call["context"], work=meter())
            self.assertEqual(call, original)
            self.assertTrue(result.affected)
            self.assertEqual(len(result.queries), 4 if kind == "replacement-registration" else 3)
            self.assertEqual(len(result.write.after_heads), 9 if kind == "replacement-registration" else 0)
            self.assertEqual(len(result.counted_after_heads), 9)
            self.assertEqual(tuple(head.index_id for head in result.write.after_heads),
                proof.heads._recovery_write_ids(proof.OPERATION) if kind == "replacement-registration" else ())
            for root in result.write.primary.business_after_roots:
                rows = [row["row"] for row in call["selected_rows"] if row["table"] == root.table and row["present"]]
                changes = [mutation for mutation in result.mutations if mutation["table"] == root.table]
                for mutation in changes:
                    rows = [row for row in rows if all(row[name] != value for name, value in mutation["key"].items())]
                    if mutation["row"] is not None:
                        rows.append(mutation["row"])
                columns = next(item.key_columns for item in proof.terminal.contracts.primary_table_contracts(proof.OPERATION)
                    if item.table == root.table)
                self.assertEqual(root, IndependentTree(rows, table=root.table, columns=columns, revision=7 + len(changes)).root)

    def test_absence_and_inactive_targets_are_proved_noops_not_missing_work(self):
        for kind in ("replacement-registration", "lost-active-key-decommission"):
            for absent in (True, False):
                call = fixture(kind=kind, absent=absent, status="expired")
                raw = proof.produce_originals(**call, work=meter())
                result = proof.replay_originals(raw, expected_context=call["context"], work=meter())
                self.assertFalse(result.affected)
                self.assertEqual(result.mutations, ())
                self.assertEqual(len(result.queries), 1)
                self.assertEqual(result.write.after_heads, ())
                self.assertEqual(list(result.counted_after_heads), call["context"]["countedBeforeHeads"])

    def test_secondary_queries_require_the_target_membership_first(self):
        call = fixture()
        follow = proof.followup_queries(context=call["context"], target_selected=call["selected_rows"][0],
            target_proof=call["before_proofs"][0], work=meter())
        self.assertEqual(tuple(query.table for query in follow), (
            proof.terminal.retention.CHALLENGE_TABLE, proof.terminal.capacity.OUTBOX_TABLE,
            proof.terminal.capacity.AGGREGATE_TABLE))
        self.assertEqual(follow[0].absent_key, {"id": CHALLENGE})
        corrupted = copy.deepcopy(call["selected_rows"][0])
        corrupted["row"]["challenge_id"] = "00000000-0000-0000-0000-000000000002"
        with self.assertRaises(REFUSALS):
            proof.followup_queries(context=call["context"], target_selected=corrupted,
                target_proof=call["before_proofs"][0], work=meter())

    def test_read_inventory_missing_profile_and_wrong_frontier_fail_closed(self):
        for defect in ("missing-row", "extra-row", "missing-profile", "frontier"):
            call = fixture()
            if defect == "missing-row":
                call["selected_rows"] = call["selected_rows"][:-1]
                call["before_proofs"] = call["before_proofs"][:-1]
            elif defect == "extra-row":
                call["selected_rows"] += call["selected_rows"][:1]
                call["before_proofs"] += call["before_proofs"][:1]
            elif defect == "missing-profile":
                call["index_inputs"] = call["index_inputs"][:-1]
            else:
                item = next(item for item in call["index_inputs"] if item["frontier"])
                item["frontier"][0]["primaryRowDigest"] = "sha256:" + "f" * 64
            with self.subTest(defect=defect), self.assertRaises(REFUSALS):
                proof.produce_originals(**call, work=meter())

    def test_independent_context_and_canonical_wire_are_mandatory(self):
        call = fixture()
        raw = proof.produce_originals(**call, work=meter())
        for field in ("requestDigest", "databaseNow", "maximumRetained", "countedBeforeHeads"):
            expected = copy.deepcopy(call["context"])
            if field == "requestDigest":
                expected[field] = "sha256:" + "a" * 64
            elif field == "databaseNow":
                expected[field] = "2026-01-05T00:00:01+00:00"
            elif field == "maximumRetained":
                expected[field] += 1
            else:
                expected[field][0]["indexRevision"] += 1
            with self.subTest(field=field), self.assertRaises(REFUSALS):
                proof.replay_originals(raw, expected_context=expected, work=meter())
        for changed in (raw + b"\n", raw.replace(b'"schema":', b'"schema":"extra","schema":', 1)):
            with self.assertRaises(REFUSALS):
                proof.replay_originals(changed, expected_context=call["context"], work=meter())

    def test_no_witness_boolean_or_replacement_budget_can_authorize_the_component(self):
        call = fixture()
        changed = copy.deepcopy(call)
        changed["context"]["witnessClaimed"] = True
        with self.assertRaises(REFUSALS):
            proof.produce_originals(**changed, work=meter())
        work = meter(max_input_bytes=1024)
        limits = work.limits
        with self.assertRaises(REFUSALS):
            proof.produce_originals(**call, work=work)
        self.assertIs(work.limits, limits)


if __name__ == "__main__":
    unittest.main()
