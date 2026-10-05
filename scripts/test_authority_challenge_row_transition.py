#!/usr/bin/env python3
"""Real row/proof engines with independent trees; no SQL or phase admission."""
from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_challenge_retention as retention
from serverware import authority_challenge_row_transition as transition
from serverware import authority_index_projection as projection
from serverware import authority_query_read_work as measured
from serverware.authority_index_contract import IndexLeaf
from test_authority_radix_mutation import IndependentTree
from test_authority_radix_proof import sql_digest, sql_json


IDENTITY = "00000000-0000-0000-0000-000000000001"
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
REFUSALS = (ValueError, transition.core.TransitionKernelError)


def timestamp(microseconds):
    return (EPOCH + timedelta(microseconds=microseconds)).isoformat()


def row(**changes):
    value = dict(id=IDENTITY, challenge="challenge", challenge_type="registration", user_id="user",
        scope_key=None, approval_request_id=None, payload_json="{}",
        expires_at=timestamp(4_000_000), used_at=None, created_at=timestamp(1_000_000))
    value.update({name: None for name in retention.DERIVED_FIELDS})
    value["retention_reference_mask"] = 0
    value.update(changes)
    return value


def context(value=None, phase="expire", *, limits=None):
    value = row() if value is None else value
    tree = IndependentTree([value], table="webauthn_challenges", revision=7)
    selected = tree.selected({"id": value["id"]})
    work = measured._ValidationWork(limits or measured.QueryReadValidationLimits())
    return tree, dict(phase=phase, cutoff_us=5_000_000, retention_us=2_000_000,
        primary_root=tree.root, selected_row=selected, before_proof=tree.proof(selected), work=work)


class ChallengeRowTransitionTests(unittest.TestCase):
    def assert_roots_and_changes(self, original, after, result):
        expected = IndependentTree([] if after is None else [after],
            table="webauthn_challenges", revision=8)
        self.assertEqual(result.primary_after, expected.root)
        self.assertEqual(result.primary_nodes[("webauthn_challenges", 0, "")], expected.root.root_digest)
        for (_table, depth, prefix), digest in result.primary_nodes.items():
            self.assertEqual(digest, expected.nodes.get((depth, prefix), expected.empty[depth]))
        self.assertEqual(tuple(item.index_id for item in result.index_changes),
                         projection.index_ids_for_table("webauthn_challenges"))
        key_digest = result.mutation["keyDigest"]
        old_digest = sql_digest("serverware.policyAuthorityAuthenticatedRow/v1",
            b"webauthn_challenges", sql_json(original))
        new_digest = None if after is None else sql_digest("serverware.policyAuthorityAuthenticatedRow/v1",
            b"webauthn_challenges", sql_json(after))
        for item in result.index_changes:
            before = projection.project_row(item.index_id, original,
                primary_key_digest=key_digest, primary_row_digest=old_digest)
            following = None if after is None else projection.project_row(item.index_id, after,
                primary_key_digest=key_digest, primary_row_digest=new_digest)
            self.assertEqual(item.revision_delta, int(before is not None or following is not None))
            self.assertEqual(tuple(change.before for change in item.changes if change.before is not None),
                             () if before is None else (before,))
            self.assertEqual(tuple(change.after for change in item.changes if change.after is not None),
                             () if following is None else (following,))
        self.assertIs(type(result.candidate_leaf), IndexLeaf)
        self.assertEqual(result.candidate_leaf.primary_row_digest, old_digest)

    def test_expire_matches_independent_primary_tree_and_all_nine_projections(self):
        original = row()
        tree, arguments = context(original)
        before = copy.deepcopy(arguments["selected_row"])
        result = transition.evaluate_row(**arguments)
        after = dict(original, used_at=timestamp(5_000_000))
        self.assertEqual(result.primary_before, tree.root)
        self.assertEqual(result.mutation["operation"], "UPDATE")
        self.assertEqual(result.mutation["expectedRow"], original)
        self.assertEqual(result.mutation["row"], after)
        self.assertEqual(arguments["selected_row"], before)
        self.assertIsNot(result.mutation["expectedRow"], arguments["selected_row"]["row"])
        self.assertTrue(all(item.revision_delta == 1 for item in result.index_changes))
        self.assert_roots_and_changes(original, after, result)

    def test_old_and_overflow_delete_only_real_terminal_unreferenced_rows(self):
        for phase in ("old", "overflow"):
            original = row(used_at=timestamp(4_000_000))
            _tree, arguments = context(original, phase)
            result = transition.evaluate_row(**arguments)
            self.assertEqual(result.mutation["operation"], "DELETE")
            self.assertIsNone(result.mutation["row"])
            self.assertEqual(sum(item.revision_delta for item in result.index_changes), 4)
            self.assert_roots_and_changes(original, None, result)
        for phase, original in (("expire", row(used_at=timestamp(4_000_000))),
                ("expire", row(expires_at=timestamp(5_000_001))),
                ("old", row(used_at=timestamp(4_000_000), created_at=timestamp(3_000_001))),
                ("overflow", row()),
                ("old", row(used_at=timestamp(4_000_000), retention_reference_mask=1,
                    retention_recovery_id="recovery", retention_recovery_row_digest="sha256:" + "a" * 64))):
            with self.subTest(phase=phase, used=original["used_at"]):
                _tree, arguments = context(original, phase)
                with self.assertRaises(REFUSALS):
                    transition.evaluate_row(**arguments)

    def test_actual_primary_proof_and_original_work_are_required(self):
        for field in ("row", "proof", "root", "selector"):
            _tree, arguments = context()
            if field == "row":
                arguments["selected_row"]["row"]["payload_json"] = '{"changed":true}'
            elif field == "proof":
                arguments["before_proof"]["rowDigest"] = "sha256:" + "f" * 64
            elif field == "root":
                arguments["primary_root"] = replace(arguments["primary_root"], root_revision=8)
            else:
                arguments["selected_row"]["contractSelector"] = "invented"
            with self.subTest(field=field), self.assertRaises(REFUSALS):
                transition.evaluate_row(**arguments)
        _tree, arguments = context(limits=measured.QueryReadValidationLimits(max_input_bytes=1024))
        original_limits = arguments["work"].limits
        with self.assertRaises(REFUSALS):
            transition.evaluate_row(**arguments)
        self.assertIs(arguments["work"].limits, original_limits)
        _tree, arguments = context()
        with self.assertRaises(REFUSALS):
            transition.evaluate_row(**dict(arguments, phase="caller-phase"))
        with self.assertRaises(REFUSALS):
            transition.evaluate_row(**dict(arguments, cutoff_us=True))

    def test_near_one_mib_payload_fits_existing_caps_without_nine_row_copies(self):
        original = row(payload_json='"' + "x" * (1024 * 1024 - 4096) + '"')
        _tree, arguments = context(original)
        held_limits = arguments["work"].limits
        result = transition.evaluate_row(**arguments)
        self.assertEqual(result.mutation["row"]["payload_json"], original["payload_json"])
        self.assertIs(arguments["work"].limits, held_limits)
        self.assertLessEqual(arguments["work"].input_bytes, 64 * 1024 * 1024)
        self.assertLessEqual(arguments["work"].json_nodes, 1_000_000)
        self.assertEqual(len(result.index_changes), 9)


if __name__ == "__main__":
    unittest.main()
