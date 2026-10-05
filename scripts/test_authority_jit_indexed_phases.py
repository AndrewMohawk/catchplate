"""UNRUN JIT component controls using real primary/count-fold engines.

Synthetic keys/assertions and independent small-tree fixtures are reused.
Projection is the real source implementation, not an independent codec oracle.
No SQL, current root, operation admission or completed compound is asserted.
"""
from __future__ import annotations

import ast
import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_jit_indexed_phases as source
from serverware.authority_index_contract import IndexLeaf, OpaqueSubtree
from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
from test_authority_jit_assertion_replay import fixture as raw_fixture
from test_authority_radix_mutation import IndependentTree
from test_authority_radix_proof import sql_digest, sql_json
from test_authority_index_range import IndependentIndex


def meter(**values):
    return _ValidationWork(QueryReadValidationLimits(**values))


def fixture():
    raw, anchors, trees, _receipt = raw_fixture()
    document = json.loads(raw)
    context = source.receipt.core.KernelContext(source.OPERATION, document["request"]["arguments"],
        tuple(document["selectedRows"]), datetime(1970, 1, 1, tzinfo=timezone.utc)
            + timedelta(microseconds=document["databaseCutoffUs"]), document["request"]["requestDigest"])
    transition = source.receipt.transition(context, assertion_policy=anchors["assertion_policy"], work=meter())
    rows = {value["table"]: value for value in document["selectedRows"]}
    proofs = {value["table"]: value for value in document["beforeProofs"]}
    mutations = {value["table"]: value for value in transition.mutations}
    inputs = []
    for head, raw_frontier in zip(anchors["counted_before_heads"], document["writeFrontiers"], strict=True):
        records = tuple(IndexLeaf(value["key"], value["primaryKeyDigest"], value["primaryRowDigest"])
            if value["kind"] == "leaf" else OpaqueSubtree(value["prefix"], value["digest"], value["count"])
            for value in raw_frontier["frontier"])
        inputs.append(source.indexed.IndexedMutationInput(head.index_id, head.index_revision, head.index_root, records))
    selected_anchors = {key: anchors[key] for key in
        ("business_before_roots", "authorization_before_roots", "counted_before_heads")}
    return selected_anchors, rows, proofs, mutations, tuple(inputs), trees


def primary(owner, rows, proofs, mutations, works):
    for ordinal, table in enumerate(source.PRIMARY_TABLES, 1):
        if owner.verify_primary(selected_row=rows[table], before_proof=proofs[table],
                mutation=mutations[table], work=works[ordinal]) is not None:
            raise AssertionError("private primary result escaped")
    if owner.prepare_primary(works[4]) is not None:
        raise AssertionError("prepared inventory escaped")


def close(owner, inputs, works):
    observed = []
    for ordinal, raw in enumerate(inputs):
        observed.append(owner.prepare_index(works[5 + 2 * ordinal]))
        if owner.fold_index(raw, work=works[6 + 2 * ordinal]) is not None:
            raise AssertionError("partial counted result escaped")
    return observed, owner.finish(works[29])


class JitIndexedPhaseControls(unittest.TestCase):
    def test_actual_three_primary_and_twelve_counted_roots_equal_independent_trees(self):
        anchors, rows, proofs, mutations, inputs, trees = fixture()
        works = [meter() for _ in range(source.STAGE_COUNT)]
        owner = source._JitIndexedPhases(**anchors, work=works[0])
        primary(owner, rows, proofs, mutations, works)
        observations, actual = close(owner, inputs, works)
        self.assertEqual(len(actual.stage_work), 30)
        self.assertEqual(actual.result.metrics.new_row_hashes, 2)
        self.assertEqual(actual.result.metrics.primary.mutations, 3)
        self.assertEqual(tuple(head.index_id for head in actual.result.after_heads), source.heads._jit_receipt_ids())
        self.assertEqual(len(actual.result.primary.business_after_roots), 4)
        self.assertEqual(len(actual.result.primary.authorization_after_roots), 4)
        self.assertEqual(actual.result.primary.authorization_after_roots, anchors["authorization_before_roots"])
        for root in actual.result.primary.authorization_after_roots:
            self.assertEqual(root, trees[root.table].root)
        before = {root.table: root for root in anchors["business_before_roots"]}
        for root in actual.result.primary.business_after_roots:
            if root.table not in mutations:
                self.assertEqual(root, before[root.table])
                continue
            tree, mutation = trees[root.table], mutations[root.table]
            remaining = [row for row in tree.rows.values() if tree.key(row) != mutation["key"]]
            remaining.append(mutation["row"])
            expected = IndependentTree(remaining, table=root.table, columns=tree.columns,
                revision=tree.root.root_revision + 1)
            self.assertEqual(root, expected.root)
        for observation, head in zip(observations, actual.result.after_heads, strict=True):
            profile = source.projection.profile_for(head.index_id)
            row = mutations[profile.table]["row"]
            tree = trees[profile.table]
            selected = tree.selected(tree.key(row))
            digest = sql_digest("serverware.policyAuthorityAuthenticatedRow/v1",
                profile.table.encode("ascii"), sql_json(row))
            leaf = source.projection.project_row(head.index_id, row,
                primary_key_digest=selected["keyDigest"], primary_row_digest=digest)
            expected = IndependentIndex([] if leaf is None else [leaf], profile=profile)
            self.assertEqual(head.index_root, expected.root)
            delta = int(bool(observation.changes))
            self.assertEqual(head.index_revision, observation.index_revision + delta)
        self.assertEqual(sum(value.input_bytes for value in actual.stage_work), actual.total_work.input_bytes)
        self.assertTrue(all(work.input_bytes <= 64 * 1024 * 1024 for work in works))

    def test_empty_and_two_nonmember_profiles_still_fold_without_advancing_revision(self):
        anchors, rows, proofs, mutations, inputs, _trees = fixture()
        works = [meter() for _ in range(30)]
        owner = source._JitIndexedPhases(**anchors, work=works[0])
        primary(owner, rows, proofs, mutations, works)
        observations, actual = close(owner, inputs, works)
        by_id = {item.index_id: item for item in actual.result.after_heads}
        for observation in observations:
            if observation.index_id.startswith("webauthn_registration_unused_"):
                self.assertEqual(observation.changes, ())
                self.assertEqual(observation.target_keys, ())
                self.assertEqual(by_id[observation.index_id].index_root, observation.before_root)
                self.assertEqual(by_id[observation.index_id].index_revision, observation.index_revision)
        self.assertEqual(len(actual.result.metrics.indexes), 12)

    def test_original_raw_primary_proof_cas_template_kind_and_order_are_required(self):
        for defect in ("proof", "old-row", "template", "kind", "table-order"):
            anchors, rows, proofs, mutations, _inputs, _trees = fixture()
            owner = source._JitIndexedPhases(**anchors, work=meter())
            table = source.PRIMARY_TABLES[0]
            if defect == "proof":
                proofs[table]["rootDigest"] = "sha256:" + "a" * 64
            elif defect == "old-row":
                mutations[table]["expectedRow"] = {"unexpected": "original"}
            elif defect == "template":
                mutations[table]["templateId"] = "not-a-source-template"
            elif defect == "kind":
                mutations[table]["operation"] = "UPDATE"
            else:
                table = source.PRIMARY_TABLES[1]
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                owner.verify_primary(selected_row=rows[table], before_proof=proofs[table],
                    mutation=mutations[table], work=meter())
            self.assertTrue(owner._failed)

    def test_exact_original_head_frontier_and_complete_schedule_cannot_be_replaced(self):
        for defect in ("revision", "root", "boolean", "frontier", "skip"):
            anchors, rows, proofs, mutations, inputs, _trees = fixture()
            works = [meter() for _ in range(30)]
            owner = source._JitIndexedPhases(**anchors, work=works[0])
            primary(owner, rows, proofs, mutations, works)
            owner.prepare_index(works[5])
            raw = inputs[0]
            if defect == "revision":
                raw = replace(raw, index_revision=raw.index_revision + 1)
            elif defect == "root":
                raw = replace(raw, index_root=source.CountedNode("sha256:" + "a" * 64, raw.index_root.count))
            elif defect == "boolean":
                raw = replace(raw, index_revision=True)
            elif defect == "frontier":
                raw = replace(raw, frontier=(OpaqueSubtree("0", "sha256:" + "a" * 64, 1),))
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                if defect == "skip":
                    owner.finish(works[29])
                else:
                    owner.fold_index(raw, work=works[6])
            self.assertTrue(owner._failed)

    def test_independent_anchor_rosters_cannot_be_shortened_reordered_or_alias_typed(self):
        anchors, *_rest = fixture()
        for defect in ("primary-short", "primary-order", "authorization-short", "authorization-order",
                "root-class-swap", "authorization-bool", "head-short", "head-order", "bool"):
            values = copy.deepcopy(anchors)
            if defect == "primary-short":
                values["business_before_roots"] = values["business_before_roots"][:-1]
            elif defect == "primary-order":
                values["business_before_roots"] = tuple(reversed(values["business_before_roots"]))
            elif defect == "authorization-short":
                values["authorization_before_roots"] = values["authorization_before_roots"][:-1]
            elif defect == "authorization-order":
                values["authorization_before_roots"] = tuple(reversed(values["authorization_before_roots"]))
            elif defect == "root-class-swap":
                business, authorization = values["business_before_roots"], values["authorization_before_roots"]
                values["business_before_roots"] = tuple(sorted((authorization[0], *business[1:]),
                    key=lambda root: root.table))
                values["authorization_before_roots"] = tuple(sorted((business[0], *authorization[1:]),
                    key=lambda root: root.table))
            elif defect == "authorization-bool":
                object.__setattr__(values["authorization_before_roots"][0], "root_revision", True)
            elif defect == "head-short":
                values["counted_before_heads"] = values["counted_before_heads"][:-1]
            elif defect == "head-order":
                values["counted_before_heads"] = tuple(reversed(values["counted_before_heads"]))
            else:
                first, *rest = values["counted_before_heads"]
                values["counted_before_heads"] = (replace(first, index_revision=True), *rest)
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                source._JitIndexedPhases(**values, work=meter())

    def test_process_work_reset_reuse_limit_replacement_and_first_failure_poison(self):
        anchors, rows, proofs, mutations, _inputs, _trees = fixture()
        table = source.PRIMARY_TABLES[0]
        for defect in ("process", "reset", "limits", "reuse"):
            work = meter()
            owner = source._JitIndexedPhases(**anchors, work=work)
            if defect == "process":
                owner._process = (owner._process[0] + 1, owner._process[1])
            elif defect == "reset":
                work.input_bytes = 0
            elif defect == "limits":
                work.limits = QueryReadValidationLimits()
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                owner.verify_primary(selected_row=rows[table], before_proof=proofs[table],
                    mutation=mutations[table], work=work if defect == "reuse" else meter())
        class Cancel(BaseException):
            pass
        error = Cancel("synthetic cancellation")
        owner = source._JitIndexedPhases(**anchors, work=meter())
        with patch.object(source.indexed, "_verify_primary", side_effect=error):
            with self.assertRaises(Cancel) as caught:
                owner.verify_primary(selected_row=rows[table], before_proof=proofs[table],
                    mutation=mutations[table], work=meter())
        self.assertIs(caught.exception, error)
        self.assertTrue(owner._failed)
        parsed = ast.parse((Path(__file__).resolve().parents[1] / "serverware/authority_jit_indexed_phases.py").read_text())
        self.assertFalse(any(isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
            and item.func.id in {"_ValidationWork", "QueryReadValidationLimits"} for item in ast.walk(parsed)))

    def test_private_acquisition_borrows_only_same_call_engine_originals_then_requires_fold(self):
        anchors, rows, proofs, mutations, inputs, _trees = fixture()
        works = [meter() for _ in range(30)]
        owner = source._JitIndexedPhases(**anchors, work=works[0])
        primary(owner, rows, proofs, mutations, works)
        observed = owner.prepare_index(works[5])
        acquisition_work = meter()
        # No SQL or collector success is simulated here: only private custody.
        with owner._acquisition_binding(work=acquisition_work) as binding:
            item, profile, changes, delta, allowance, prepared = binding
            self.assertIs(prepared, owner._prepared)
            self.assertIs(changes, owner._pending[2])
            self.assertEqual(item.index_id, observed.index_id)
            self.assertEqual(profile.index_id, item.index_id)
            self.assertEqual(allowance, owner._pending[4])
            self.assertIn(delta, (0, 1))
            self.assertTrue(owner._busy)
            for internal, detached in zip(changes, observed.changes, strict=True):
                self.assertIsNot(internal, detached)
            acquisition_work.charge(input_bytes=19)
        self.assertEqual(owner._phase, 6)
        self.assertEqual(len(owner._work_metrics), 6)
        owner.fold_index(inputs[0], work=works[6])
        self.assertEqual(owner._phase, 7)
        self.assertFalse(owner._busy)

    def test_acquisition_cannot_replace_metadata_reenter_reuse_or_leave_changed_limits(self):
        for defect in ("head", "authorization-root", "change", "count", "limits", "reenter", "repeat", "reuse"):
            anchors, rows, proofs, mutations, inputs, _trees = fixture()
            works = [meter() for _ in range(30)]
            owner = source._JitIndexedPhases(**anchors, work=works[0])
            primary(owner, rows, proofs, mutations, works)
            owner.prepare_index(works[5])
            work = works[5] if defect == "reuse" else meter()
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                with owner._acquisition_binding(work=work) as binding:
                    item, _profile, changes, _delta, _allowance, prepared = binding
                    if defect == "head":
                        object.__setattr__(item.index_root, "count", bool(item.index_root.count))
                    elif defect == "authorization-root":
                        object.__setattr__(owner._authorization[0], "root_revision", True)
                    elif defect == "change":
                        object.__setattr__(changes[0].after, "primary_row_digest", "sha256:" + "a" * 64)
                    elif defect == "count":
                        prepared.primary_after_counts["webauthn_challenges"] = True
                    elif defect == "limits":
                        work.limits = QueryReadValidationLimits()
                    elif defect == "reenter":
                        owner.fold_index(inputs[0], work=works[6])
                if defect == "repeat":
                    with owner._acquisition_binding(work=meter()):
                        self.fail("second acquisition entered")
            self.assertTrue(owner._failed)


if __name__ == "__main__":
    unittest.main()
