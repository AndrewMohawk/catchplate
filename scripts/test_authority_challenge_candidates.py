#!/usr/bin/env python3
"""Candidate observations and an independent full-list merge oracle.

Source projections and BusinessKey hashes are real; heads, prior changes and
raw pages are component fixtures. No membership, range/rank completeness,
actual SQL snapshot, signed parent or mutation authority is claimed here.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_candidates as candidates
from catchplate import authority_index_projection as projection
from catchplate import authority_query_read_work as measured
from catchplate import authority_transition_core as core
from catchplate.authority_index_contract import CountedNode, KeyInterval
from catchplate.authority_index_heads import CapturedIndexHead
from catchplate.authority_index_mutation import IndexLeafChange
from test_authority_radix_proof import sql_digest, sql_json, wire_digest, wire_json


def work(*, maximum=None):
    limits = measured.QueryReadValidationLimits() if maximum is None else measured.QueryReadValidationLimits(
        max_input_bytes=maximum)
    return measured._ValidationWork(limits)


def identity(ordinal):
    return f"00000000-0000-0000-0000-{ordinal:012x}"


def pair(ordinal, phase="expire", *, changed=False, earlier=False):
    value = dict(id=identity(ordinal), challenge_type="registration", user_id="user", scope_key="scope",
        expires_at="2026-01-01T00:04:00+00:00" if earlier else "2026-01-01T00:05:00+00:00",
        used_at=("2026-01-01T00:00:00+00:00" if earlier else "2026-01-01T00:01:00+00:00")
            if phase in {"old", "overflow"} else None,
        retention_reference_mask=0, payload_json='{"changed":true}' if changed else "{}")
    key = wire_digest("catchplate.policyAuthorityBusinessKey/v1", b"webauthn_challenges",
                      wire_json({"id": value["id"]}))
    digest = sql_digest("catchplate.policyAuthorityAuthenticatedRow/v1", b"webauthn_challenges", sql_json(value))
    leaf = projection.project_row(candidates.source.PHASE_INDEX[phase], value,
                                 primary_key_digest=key, primary_row_digest=digest)
    return leaf, value["id"]


def layer(*changes):
    return tuple(sorted(changes, key=lambda change: change.key))


def fixture(base, *, phase="expire", expected=2, retained=0, mutations=0, layers=(), changed=(), interval=None):
    profile = projection.profile_for(candidates.source.PHASE_INDEX[phase])
    head = CapturedIndexHead(profile.index_id, profile.table, projection.COUNTED_PROFILE,
        profile.projection_digest, projection.projection_manifest_digest(), 7,
        CountedNode(wire_digest("synthetic-candidate-head/v1", phase.encode("ascii")), len(base)))
    arguments = dict(phase=phase, head=head, interval=interval or KeyInterval("0" * 160, None),
        expected_rows=expected, retained_limit=retained, prior_mutations=mutations,
        change_layers=layers, changed_ids=tuple((leaf.primary_key_digest, name) for leaf, name in changed))
    return arguments


def pages(arguments, base, owner):
    head, interval = arguments["head"], arguments["interval"]
    ordered = sorted((item for item in base if interval.lower <= item[0].key
        and (interval.upper is None or item[0].key < interval.upper)),
        key=lambda item: item[0].key, reverse=arguments["phase"] == "overflow")
    result = []
    for ordinal in range(owner.page_count):
        offset = owner.base_offset + ordinal * 256
        result.append(dict(schema=candidates.source.SCHEMA, phase=arguments["phase"], indexId=head.index_id,
            projectionDigest=head.projection_digest, indexRevision=head.index_revision,
            rootDigest=head.index_root.digest, rootCount=head.index_root.count,
            lower=interval.lower, upper=interval.upper, baseOffset=owner.base_offset, ordinal=ordinal,
            leaves=[dict(key=leaf.key, primaryKeyDigest=leaf.primary_key_digest,
                         primaryRowDigest=leaf.primary_row_digest, primaryId=name)
                    for leaf, name in ordered[offset:offset + 256]]))
    return result


def oracle(arguments, base):
    """Replay all fixture changes over the full base, not the bounded window."""
    current = {leaf.key: (leaf, name) for leaf, name in base}
    names = dict(arguments["changed_ids"])
    for changes in arguments["change_layers"]:
        for change in changes:
            actual = current.get(change.key)
            assert (None if actual is None else actual[0]) == change.before
            if change.after is None:
                current.pop(change.key)
            else:
                current[change.key] = change.after, names[change.after.primary_key_digest]
    interval = arguments["interval"]
    ordered = sorted((item for item in current.values() if interval.lower <= item[0].key
        and (interval.upper is None or item[0].key < interval.upper)),
        key=lambda item: item[0].key, reverse=arguments["phase"] == "overflow")
    start = arguments["retained_limit"] if arguments["phase"] == "overflow" else 0
    return tuple(name for _leaf, name in ordered[start:start + arguments["expected_rows"]])


class ChallengeCandidateTests(unittest.TestCase):
    def consume_all(self, owner, raw_pages):
        for raw in raw_pages:
            owner.consume(body_bytes=core.canonical_bytes(raw), work=work())

    def test_all_four_phases_return_only_ids_in_source_order_once(self):
        for phase in candidates.source.PHASE_INDEX:
            with self.subTest(phase=phase):
                base = [pair(index, phase) for index in range(5)]
                arguments = fixture(base, phase=phase, retained=1 if phase == "overflow" else 0)
                owner = candidates._CandidateWindow(**arguments, work=work())
                self.consume_all(owner, pages(arguments, base, owner))
                self.assertEqual(owner.finish(work=work()), oracle(arguments, base))
                self.assertEqual(owner.received_pages, owner.page_count)
                with self.assertRaises(candidates.ChallengeCandidateError):
                    owner.finish(work=work())

    def test_chronological_replacements_moves_and_insert_delete_match_full_oracle(self):
        base = [pair(index) for index in range(12)]
        before, middle, after = base[1][0], pair(1, changed=True)[0], pair(1, changed=True, earlier=True)[0]
        transient = pair(40)
        layers = (layer(IndexLeafChange(before.key, before, middle),
                        IndexLeafChange(transient[0].key, None, transient[0])),
                  layer(IndexLeafChange(middle.key, middle, None), IndexLeafChange(after.key, None, after),
                        IndexLeafChange(transient[0].key, transient[0], None)))
        arguments = fixture(base, expected=5, mutations=4, layers=layers, changed=(base[1], transient))
        owner = candidates._CandidateWindow(**arguments, work=work())
        self.consume_all(owner, pages(arguments, base, owner))
        self.assertEqual(owner.finish(work=work()), oracle(arguments, base))
        broken = (layers[0], layer(IndexLeafChange(before.key, before, None)))
        with self.assertRaises(candidates.ChallengeCandidateError):
            candidates._CandidateWindow(**dict(arguments, change_layers=broken), work=work())

    def test_overflow_prefix_same_key_update_move_and_outside_interval_old(self):
        base = [pair(index * 2, "overflow") for index in range(100)]
        deleted, updated, moved, outside = base[98], base[97], base[96], base[99]
        replacement = pair(194, "overflow", changed=True)
        following = pair(192, "overflow", earlier=True)
        inserted = pair(195, "overflow")
        changes = layer(IndexLeafChange(deleted[0].key, deleted[0], None),
            IndexLeafChange(updated[0].key, updated[0], replacement[0]),
            IndexLeafChange(moved[0].key, moved[0], None), IndexLeafChange(following[0].key, None, following[0]),
            IndexLeafChange(outside[0].key, outside[0], None), IndexLeafChange(inserted[0].key, None, inserted[0]))
        arguments = fixture(base, phase="overflow", expected=5, retained=20, mutations=5,
            layers=(changes,), changed=(deleted, updated, moved, outside, inserted),
            interval=KeyInterval("0" * 160, outside[0].key))
        owner = candidates._CandidateWindow(**arguments, work=work())
        self.assertEqual(owner.base_offset, 10)
        self.consume_all(owner, pages(arguments, base, owner))
        self.assertEqual(owner.finish(work=work()), oracle(arguments, base))

    def test_exact_page_schedule_full_final_pages_and_empty_tail_are_required(self):
        base = [pair(index) for index in range(513)]
        arguments = fixture(base, expected=256, mutations=64)
        owner = candidates._CandidateWindow(**arguments, work=work())
        raw_pages = pages(arguments, base, owner)
        self.assertEqual([len(raw["leaves"]) for raw in raw_pages], [256, 256])
        self.consume_all(owner, raw_pages)
        self.assertEqual(owner.finish(work=work()), oracle(arguments, base))
        arguments = fixture(base[:1], expected=1, mutations=128)
        owner = candidates._CandidateWindow(**arguments, work=work())
        raw_pages = pages(arguments, base[:1], owner)
        self.assertEqual([len(raw["leaves"]) for raw in raw_pages], [1, 0, 0])
        self.consume_all(owner, raw_pages)
        self.assertEqual(owner.finish(work=work()), (base[0][1],))
        for variant in ("missing", "skipped", "extra", "after-short"):
            owner = candidates._CandidateWindow(**arguments, work=work())
            raw_pages = pages(arguments, base[:1], owner)
            with self.assertRaises(candidates.ChallengeCandidateError):
                if variant == "missing":
                    self.consume_all(owner, raw_pages[:-1])
                    owner.finish(work=work())
                elif variant == "skipped":
                    self.consume_all(owner, raw_pages[1:])
                elif variant == "extra":
                    self.consume_all(owner, raw_pages + raw_pages[-1:])
                else:
                    raw_pages[1]["leaves"] = copy.deepcopy(raw_pages[0]["leaves"])
                    self.consume_all(owner, raw_pages)

    def test_raw_context_order_ids_and_noncanonical_bytes_refuse_and_poison(self):
        base = [pair(index) for index in range(3)]
        arguments = fixture(base)
        for variant in ("root", "bool", "id", "suffix", "order", "duplicate", "field", "canonical"):
            with self.subTest(variant=variant):
                owner = candidates._CandidateWindow(**arguments, work=work())
                raw = pages(arguments, base, owner)[0]
                if variant == "root":
                    raw["rootDigest"] = "sha256:" + "f" * 64
                elif variant == "bool":
                    raw["baseOffset"] = False
                elif variant == "id":
                    raw["leaves"][0]["primaryId"] = identity(40)
                elif variant == "suffix":
                    raw["leaves"][0]["key"] = raw["leaves"][0]["key"][:-1] + "1"
                elif variant == "order":
                    raw["leaves"].reverse()
                elif variant == "duplicate":
                    raw["leaves"].append(raw["leaves"][-1])
                elif variant == "field":
                    raw["accepted"] = True
                encoded = core.canonical_bytes(raw) + (b" " if variant == "canonical" else b"")
                with self.assertRaises(ValueError):
                    owner.consume(body_bytes=encoded, work=work())
                with self.assertRaises(candidates.ChallengeCandidateError):
                    owner.finish(work=work())

    def test_closed_geometry_original_context_work_and_incomplete_results(self):
        base = [pair(0)]
        arguments = fixture(base, expected=1)
        for changes in ({"expected_rows": True}, {"expected_rows": 0}, {"prior_mutations": 1537},
                        {"changed_ids": ((base[0][0].primary_key_digest, base[0][1]),)},
                        {"change_layers": ((),) * 7}):
            with self.assertRaises(candidates.ChallengeCandidateError):
                candidates._CandidateWindow(**dict(arguments, **changes), work=work())
        owner = candidates._CandidateWindow(**dict(arguments, expected_rows=256, prior_mutations=1536), work=work())
        self.assertEqual(owner.page_count, 25)
        for variant in ("original", "work", "insufficient"):
            owner = candidates._CandidateWindow(**arguments, work=work())
            raw = pages(arguments, base, owner)[0]
            if variant == "original":
                owner._anchors["indexRevision"] += 1
            if variant == "insufficient":
                raw["leaves"] = []
                self.consume_all(owner, [raw])
                with self.assertRaises(candidates.ChallengeCandidateError):
                    owner.finish(work=work())
            else:
                with self.assertRaises(ValueError):
                    owner.consume(body_bytes=core.canonical_bytes(raw), work=work(maximum=1) if variant == "work" else work())
            with self.assertRaises(candidates.ChallengeCandidateError):
                owner.finish(work=work())


if __name__ == "__main__":
    unittest.main()
