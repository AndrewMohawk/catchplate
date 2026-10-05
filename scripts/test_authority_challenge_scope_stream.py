#!/usr/bin/env python3
"""Raw synthetic scope evidence with real primary/count/range engines."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_challenge_counts as counts
from serverware import authority_challenge_maintenance as maintenance
from serverware import authority_challenge_scope_stream as stream
from serverware import authority_index_projection as projection
from serverware import authority_query_read_work as measured
from serverware.authority_index_contract import IndexLeaf
from serverware.authority_index_heads import CapturedIndexHead
from test_authority_challenge_row_transition import row
from test_authority_index_range import IndependentIndex
from test_authority_index_range_count import count_frontier
from test_authority_radix_mutation import IndependentTree


REFUSALS = (ValueError, maintenance.ChallengeMaintenanceError)


def work():
    return measured._ValidationWork(measured.QueryReadValidationLimits())


def fixture(values):
    primary = IndependentTree(values, table="webauthn_challenges", revision=17)
    profile = projection.profile_for("webauthn_challenge_scope_unused")
    interval = projection.query_interval(profile.index_id,
        dict(challenge_type="registration", user_id="user", scope_key="scope"))
    pairs, leaves = [], []
    for value in values:
        selected = primary.selected({"id": value["id"]})
        proof = primary.proof(selected)
        pairs.append((selected, proof))
        leaf = projection.project_row(profile.index_id, value,
            primary_key_digest=selected["keyDigest"], primary_row_digest=proof["rowDigest"])
        if leaf is not None:
            leaves.append(leaf)
    counted = IndependentIndex(leaves, profile=profile)
    head = CapturedIndexHead(profile.index_id, "webauthn_challenges", projection.COUNTED_PROFILE,
        profile.projection_digest, projection.projection_manifest_digest(), 17, counted.root)
    raw_count = dict(schema=counts.SCHEMA, role=counts.SCOPE_ROLE, indexId=profile.index_id,
        indexRevision=17, rootDigest=counted.root.digest, rootCount=counted.root.count,
        lower=interval.lower, upper=interval.upper,
        frontier=[dict(prefix=node.prefix, digest=node.digest, count=node.count)
                  for node in count_frontier(counted, interval)])
    raw_range = dict(schema=maintenance.RANGE_SCHEMA, frontier=[
        dict(kind="leaf", key=node.key, primaryKeyDigest=node.primary_key_digest,
             primaryRowDigest=node.primary_row_digest) if type(node) is IndexLeaf else
        dict(kind="opaque", prefix=node.prefix, digest=node.digest, count=node.count)
        for node in counted.frontier(interval)])
    arguments = dict(challenge_type="registration", user_id="user", scope_key="scope", replace_scope=True,
        primary_root=primary.root, index_head=head, count_evidence=raw_count)
    return arguments, pairs, raw_range


def selected_rows(count=2, *, payload="{}"):
    return [row(id=f"00000000-0000-0000-0000-{index:012x}", scope_key="scope", payload_json=payload)
            for index in range(count)]


class ChallengeScopeStreamTests(unittest.TestCase):
    def test_exact_scope_membership_range_and_mask_zero_slots(self):
        values = selected_rows()
        values[1].update(retention_reference_mask=1, retention_recovery_id="recovery",
                         retention_recovery_row_digest="sha256:" + "a" * 64)
        arguments, pairs, raw_range = fixture(values)
        owner = stream._StreamingScope(**arguments, work=work())
        self.assertEqual(owner.expected_rows, 2)
        for selected, proof in pairs:
            owner.consume(selected_row=selected, before_proof=proof, work=work())
        result = owner.finish(range_evidence=raw_range, work=work())
        self.assertEqual(result, stream._ScopeSummary(2, 1, False))
        self.assertEqual(set(result.__dataclass_fields__), {"count", "terminal_slots", "overflow"})
        with self.assertRaises(stream.ChallengeScopeStreamError):
            owner.finish(range_evidence=raw_range, work=work())

    def test_disabled_empty_and_authenticated_overflow_have_exact_evidence_rules(self):
        arguments, pairs, raw_range = fixture(selected_rows())
        for changes in ({"replace_scope": False}, {"scope_key": None}):
            disabled = dict(arguments, count_evidence=None, **changes)
            owner = stream._StreamingScope(**disabled, work=work())
            self.assertEqual(owner.expected_rows, 0)
            self.assertEqual(owner.finish(range_evidence=None, work=work()), stream._ScopeSummary(0, 0, False))
            with self.assertRaises(stream.ChallengeScopeStreamError):
                stream._StreamingScope(**dict(arguments, **changes), work=work())
        empty, _pairs, empty_range = fixture([])
        owner = stream._StreamingScope(**empty, work=work())
        self.assertEqual(owner.finish(range_evidence=empty_range, work=work()), stream._ScopeSummary(0, 0, False))
        overflow, pairs, _raw_range = fixture(selected_rows(256))
        owner = stream._StreamingScope(**overflow, work=work())
        self.assertEqual(owner.expected_rows, 0)
        self.assertEqual(owner.finish(range_evidence=None, work=work()), stream._ScopeSummary(256, 0, True))
        owner = stream._StreamingScope(**overflow, work=work())
        with self.assertRaises(stream.ChallengeScopeStreamError):
            owner.consume(selected_row=pairs[0][0], before_proof=pairs[0][1], work=work())
        owner = stream._StreamingScope(**overflow, work=work())
        with self.assertRaises(stream.ChallengeScopeStreamError):
            owner.finish(range_evidence=raw_range, work=work())

    def test_primary_count_range_order_and_original_context_cannot_be_substituted(self):
        arguments, pairs, raw_range = fixture(selected_rows())
        for variant in ("duplicate", "reverse", "proof", "count", "range", "context", "missing"):
            with self.subTest(variant=variant):
                selected_arguments = copy.deepcopy(arguments)
                if variant == "count":
                    selected_arguments["count_evidence"]["rootCount"] += 1
                    with self.assertRaises(REFUSALS):
                        stream._StreamingScope(**selected_arguments, work=work())
                    continue
                owner = stream._StreamingScope(**selected_arguments, work=work())
                if variant == "context":
                    owner._request["userId"] = "other"
                    with self.assertRaises(stream.ChallengeScopeStreamError):
                        owner.consume(selected_row=pairs[0][0], before_proof=pairs[0][1], work=work())
                elif variant == "proof":
                    proof = dict(pairs[0][1], rootRevision=18)
                    with self.assertRaises(REFUSALS):
                        owner.consume(selected_row=pairs[0][0], before_proof=proof, work=work())
                else:
                    order = (1, 0) if variant == "reverse" else (0, 0) if variant == "duplicate" else (0, 1)
                    owner.consume(selected_row=pairs[order[0]][0], before_proof=pairs[order[0]][1], work=work())
                    if variant in ("duplicate", "reverse"):
                        with self.assertRaises(REFUSALS):
                            owner.consume(selected_row=pairs[order[1]][0], before_proof=pairs[order[1]][1], work=work())
                    elif variant == "missing":
                        with self.assertRaises(stream.ChallengeScopeStreamError):
                            owner.finish(range_evidence=raw_range, work=work())
                    else:
                        owner.consume(selected_row=pairs[1][0], before_proof=pairs[1][1], work=work())
                        wrong = copy.deepcopy(raw_range)
                        wrong["frontier"].pop()
                        with self.assertRaises(REFUSALS):
                            owner.finish(range_evidence=wrong, work=work())
                with self.assertRaises(stream.ChallengeScopeStreamError):
                    owner.finish(range_evidence=raw_range, work=work())

    def test_per_row_payload_work_is_bounded_and_full_rows_are_not_retained(self):
        arguments, pairs, raw_range = fixture(selected_rows(payload='"' + "x" * (1024 * 1024 - 4096) + '"'))
        owner = stream._StreamingScope(**arguments, work=work())
        for selected, proof in pairs:
            budget = work()
            held_limits = budget.limits
            owner.consume(selected_row=selected, before_proof=proof, work=budget)
            self.assertIs(budget.limits, held_limits)
            self.assertLessEqual(budget.input_bytes, 64 * 1024 * 1024)
            self.assertLess(len(repr(vars(owner))), 20000)
        self.assertEqual(owner.finish(range_evidence=raw_range, work=work()), stream._ScopeSummary(2, 2, False))


if __name__ == "__main__":
    unittest.main()
