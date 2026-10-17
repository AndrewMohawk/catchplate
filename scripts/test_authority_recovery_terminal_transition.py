#!/usr/bin/env python3
"""Real relative row engines; independent primary trees, no population claim.

No DB, authority currentness, complete range/rank, witness or registry is
substituted. These controls do not establish a runnable recovery successor.
"""
from __future__ import annotations

import copy
from dataclasses import fields, replace
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_recovery_terminal_transition as transition
from test_authority_radix_mutation import IndependentTree
from test_authority_radix_proof import sql_digest, sql_json
import test_authority_recovery_terminal as original


terminal = transition.terminal
CHALLENGE_ID = "00000000-0000-0000-0000-000000000001"
REFUSALS = (ValueError, transition.core.TransitionKernelError)


def fixture(phase="expire", *, used=None, **changes):
    operation = terminal.recovery.EXPIRE if phase == "expire" else terminal.recovery.PRUNE
    table = terminal.REVOCATIONS if phase.startswith("revocation") else terminal.CEREMONIES
    if table == terminal.CEREMONIES:
        row = original.ceremony(challenge_id=CHALLENGE_ID, **changes)
        joined = original.challenge(row, id=CHALLENGE_ID, used_at=used)
        values = {table: [row], terminal.retention.CHALLENGE_TABLE: [joined]}
    else:
        row = original.revocation(**changes)
        values = {table: [row]}
    business, authorization, selected, proofs = [], [], [], []
    trees = {}
    for source in terminal.contracts.primary_table_contracts(operation):
        tree = IndependentTree(values.get(source.table, []), table=source.table,
            columns=source.key_columns, revision=7)
        trees[source.table] = tree
        (business if source.root_class == "business" else authorization).append(tree.root)
        if source.table in values:
            observed = tree.selected({"id": values[source.table][0]["id"]})
            selected.append(observed)
            proofs.append(tree.proof(observed))
    context = transition.core.KernelContext(operation, {}, tuple(selected), original.NOW, original.REQUEST)
    return trees, dict(phase=phase, context=context, business_before_roots=tuple(business),
        authorization_before_roots=tuple(authorization), before_proofs=tuple(proofs),
        terminal_retention_seconds=86_400, maximum_retained=100, work=original.meter())


class RecoveryTerminalTransitionControls(unittest.TestCase):
    def assert_actual_roots_and_changes(self, trees, result):
        mutations = {mutation["table"]: mutation for mutation in result.mutations}
        expected = {}
        for before in (*result.business_before_roots, *result.authorization_before_roots):
            mutation = mutations.get(before.table)
            if mutation is None:
                expected[before.table] = trees[before.table]
            else:
                expected[before.table] = IndependentTree(
                    [] if mutation["row"] is None else [mutation["row"]],
                    table=before.table, revision=before.root_revision + 1)
        for after in (*result.business_after_roots, *result.authorization_after_roots):
            self.assertEqual(after, expected[after.table].root)
        for (table, depth, prefix), digest in result.primary_nodes.items():
            tree = expected[table]
            self.assertEqual(digest, tree.nodes.get((depth, prefix), tree.empty[depth]))
        self.assertEqual(tuple(item.index_id for item in result.index_changes),
            transition.projection.index_ids_for_table(terminal.retention.CHALLENGE_TABLE))
        challenge = mutations.get(terminal.retention.CHALLENGE_TABLE)
        for item in result.index_changes:
            projected = []
            for field in ("expectedRow", "row"):
                image = None if challenge is None else challenge[field]
                digest = None if image is None else sql_digest(
                    "catchplate.policyAuthorityAuthenticatedRow/v1",
                    terminal.retention.CHALLENGE_TABLE.encode(), sql_json(image))
                projected.append(None if image is None else transition.projection.project_row(item.index_id,
                    image, primary_key_digest=challenge["keyDigest"], primary_row_digest=digest))
            before, after = projected
            self.assertEqual(item.revision_delta, int(before is not None or after is not None))
            self.assertEqual(tuple(change.before for change in item.changes if change.before is not None),
                () if before is None else (before,))
            self.assertEqual(tuple(change.after for change in item.changes if change.after is not None),
                () if after is None else (after,))

    def test_expire_genuine_two_row_overlay_and_nine_source_projections(self):
        for status, used in (("pending_candidate", None), ("prepared", original.EARLIER)):
            trees, call = fixture(status=status, used=used, candidate_json='{"unchanged":true}')
            held = copy.deepcopy((call["context"].selected_rows, call["before_proofs"]))
            result = transition.evaluate_row(**call)
            self.assertEqual((call["context"].selected_rows, call["before_proofs"]), held)
            self.assertEqual(len(result.mutations), 2)
            mutations = {item["table"]: item for item in result.mutations}
            ceremony = mutations[terminal.CEREMONIES]["row"]
            challenge = mutations[terminal.retention.CHALLENGE_TABLE]["row"]
            self.assertEqual(ceremony["status"], "expired")
            self.assertEqual(ceremony["candidate_json"], '{"unchanged":true}')
            self.assertEqual(challenge["used_at"], used or original.NOW.isoformat())
            self.assertEqual(challenge["retention_recovery_row_digest"], sql_digest(
                "catchplate.policyAuthorityAuthenticatedRow/v1", terminal.CEREMONIES.encode(), sql_json(ceremony)))
            self.assert_actual_roots_and_changes(trees, result)

    def test_four_prune_relative_phases_actual_deletion_and_unchanged_profiles(self):
        for phase in terminal._PHASES:
            trees, call = fixture(phase, status="expired", consumed_at=original.EARLIER)
            result = transition.evaluate_row(**call)
            deleted = [item for item in result.mutations if item["operation"] == "DELETE"]
            self.assertEqual(len(deleted), 1)
            self.assertIsNone(deleted[0]["row"])
            if phase.startswith("ceremony"):
                challenge = next(item["row"] for item in result.mutations
                    if item["table"] == terminal.retention.CHALLENGE_TABLE)
                self.assertEqual(challenge["retention_reference_mask"], 0)
                self.assertIsNone(challenge["retention_recovery_row_digest"])
            else:
                self.assertTrue(all(item.changes == () and item.revision_delta == 0
                    for item in result.index_changes))
            self.assert_actual_roots_and_changes(trees, result)

    def test_predicates_coalesce_and_population_authority_are_not_invented(self):
        for phase, changes in (("expire", {"status": "consumed"}),
                ("ceremony-old", {"status": "expired", "consumed_at": original.NOW.isoformat(),
                    "invalidated_at": original.EARLIER, "expires_at": original.EARLIER})):
            _trees, call = fixture(phase, **changes)
            with self.subTest(phase=phase), self.assertRaises(REFUSALS):
                transition.evaluate_row(**call)
        # Overflow can derive relative row effects, but never certifies rank.
        _trees, call = fixture("ceremony-overflow", status="expired", consumed_at=original.NOW.isoformat())
        result = transition.evaluate_row(**call)
        self.assertEqual({field.name for field in fields(result)}, {"phase", "mutations",
            "business_before_roots", "authorization_before_roots", "business_after_roots",
            "authorization_after_roots", "primary_nodes", "index_changes"})
        with self.assertRaises(REFUSALS):
            transition.evaluate_row(**dict(call, context=replace(call["context"], operation=terminal.recovery.INVALIDATE)))

    def test_tampered_raw_membership_and_incomplete_roots_refuse(self):
        for change in ("row", "proof", "root", "selector", "inline", "missing-root"):
            _trees, call = fixture()
            if change == "row":
                call["context"].selected_rows[0]["row"]["user_id"] = "substituted"
            elif change == "proof":
                call["before_proofs"][0]["rowDigest"] = "sha256:" + "f" * 64
            elif change == "root":
                call["business_before_roots"] = (replace(call["business_before_roots"][0], root_revision=8),
                    *call["business_before_roots"][1:])
            elif change == "selector":
                call["context"].selected_rows[0]["contractSelector"] = "invented"
            elif change == "inline":
                row = next(item["row"] for item in call["context"].selected_rows
                    if item["table"] == terminal.retention.CHALLENGE_TABLE)
                row["retention_recovery_row_digest"] = "sha256:" + "f" * 64
            else:
                call["business_before_roots"] = call["business_before_roots"][:-1]
            with self.subTest(change=change), self.assertRaises(REFUSALS):
                transition.evaluate_row(**call)

    def test_original_work_precharges_before_any_engine_and_never_renews(self):
        _trees, call = fixture()
        call["work"] = original.meter(max_input_bytes=1024)
        held = call["work"].limits
        with mock.patch.object(terminal, "evaluate_row", side_effect=AssertionError("engine ran before reservation")):
            with self.assertRaises(REFUSALS):
                transition.evaluate_row(**call)
        self.assertIs(call["work"].limits, held)
        _trees, call = fixture()
        held = call["work"].limits
        call["work"].charge(input_bytes=123, json_nodes=7, hashes=3)
        transition.evaluate_row(**call)
        self.assertIs(call["work"].limits, held)
        self.assertGreater(call["work"].input_bytes, 8 * 1024 * 1024 + 123)
        for field in ("terminal_retention_seconds", "maximum_retained"):
            _trees, call = fixture()
            with self.subTest(field=field), self.assertRaises(REFUSALS):
                transition.evaluate_row(**dict(call, **{field: True}))


if __name__ == "__main__":
    unittest.main()
