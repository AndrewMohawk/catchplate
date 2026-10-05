"""Pure raw-page commitments with independent framing; no authority or SQL."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_challenge_manifest as manifest
from serverware import authority_challenge_maintenance as maintenance
from serverware import authority_index_projection as projection
from serverware import authority_radix_mutation as primary
from serverware import authority_radix_proof as radix
from serverware.authority_index_contract import empty_node
from serverware.authority_index_heads import CapturedIndexHead
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


def work():
    return _ValidationWork(QueryReadValidationLimits())


def context():
    root = primary.PrimaryRoot("webauthn_challenges", 0, radix.empty_digest(0), 0)
    heads = []
    for identity in manifest.WRITE_IDS:
        profile = projection.profile_for(identity)
        heads.append(maintenance.head_wire(CapturedIndexHead(identity, "webauthn_challenges",
            projection.COUNTED_PROFILE, profile.projection_digest,
            projection.projection_manifest_digest(), 0, empty_node(profile, ""))))
    return dict(sourceRevision=manifest.contract.SOURCE_REVISION,
        operation="webauthn.challenge.maintain", operationId="sha256:" + "a" * 64,
        requestDigest="sha256:" + "b" * 64, configurationDigest="sha256:" + "c" * 64,
        cutoffUs=5_000_000, retentionUs=2_000_000, maximumRetained=1000,
        challengeType="registration", userId="user", scopeKey=None, replaceScope=False,
        primaryRoot=root.json_projection(), indexHeads=heads, originalDeadlineNs=123456789)


def independent_frame(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    framed = manifest.DOMAIN.encode("ascii") + b"\x00" + len(raw).to_bytes(8, "big") + raw
    return "sha256:" + hashlib.sha256(framed).hexdigest()


class ChallengeManifestTests(unittest.TestCase):
    def test_all_eighty_nine_groups_exist_and_zero_chains_match_independent_framing(self):
        selected = context()
        meter = work()
        owner = manifest.MaintenanceManifest(context=selected, work=meter)
        selected["userId"] = "later caller mutation"
        result = owner.finish(work=meter)
        self.assertEqual(len(result["groups"]), 89)
        self.assertEqual(result["context"]["userId"], "user")
        for group, row in zip(manifest.GROUPS, result["groups"], strict=True):
            phase, kind, identity = group
            self.assertEqual((row["phaseOrdinal"], row["kind"], row["indexId"]), group)
            self.assertEqual((row["pageCount"], row["byteCount"]), (0, 0))
            self.assertEqual(row["chainDigest"], independent_frame({"context": result["context"],
                "schedule": result["schedule"], "phaseOrdinal": phase, "kind": kind, "indexId": identity}))
        self.assertGreater(meter.hash_work, 89)
        with self.assertRaises(manifest.ChallengeManifestError):
            owner.finish(work=work())

    def test_streamed_actual_bodies_match_independent_chain_and_second_replay(self):
        selected = context()
        outputs = []
        bodies = (b"original raw primary page one", b"original raw primary page two")
        for _ in range(2):
            owner = manifest.MaintenanceManifest(context=selected, work=work())
            for ordinal, body in enumerate(bodies):
                actual = owner.append(phase_ordinal=0, kind="primary", index_id="",
                    ordinal=ordinal, body_bytes=body, work=work())
                self.assertEqual(actual, {"byteCount": len(body),
                    "digest": "sha256:" + hashlib.sha256(body).hexdigest()})
            outputs.append(owner.finish(work=work()))
        manifest.compare_manifest(expected=outputs[0], actual=outputs[1], work=work())
        row = next(row for row in outputs[0]["groups"] if
            (row["phaseOrdinal"], row["kind"]) == (0, "primary"))
        expected = independent_frame({"context": selected, "schedule": outputs[0]["schedule"],
            "phaseOrdinal": 0, "kind": "primary", "indexId": ""})
        for ordinal, body in enumerate(bodies):
            expected = independent_frame({"previous": expected, "ordinal": ordinal,
                "byteCount": len(body), "digest": "sha256:" + hashlib.sha256(body).hexdigest()})
        self.assertEqual(row["chainDigest"], expected)
        self.assertEqual(row["pageCount"], 2)
        self.assertEqual(row["byteCount"], sum(map(len, bodies)))
        self.assertNotIn(bodies[0].decode(), json.dumps(outputs[0]))

    def test_changed_omitted_reordered_and_mistyped_summaries_are_refused(self):
        owner = manifest.MaintenanceManifest(context=context(), work=work())
        original = owner.finish(work=work())
        changes = (
            lambda value: value["groups"].pop(),
            lambda value: value["groups"].reverse(),
            lambda value: value["groups"][0].update(pageCount=True),
            lambda value: value["groups"][0].update(chainDigest="sha256:" + "e" * 64),
            lambda value: value["groups"][0].update(extra=0),
            lambda value: value["context"].update(originalDeadlineNs=True),
            lambda value: value["schedule"].update(passes=2),
        )
        for change in changes:
            modified = copy.deepcopy(original)
            change(modified)
            with self.subTest(change=change), self.assertRaises(ValueError):
                manifest.compare_manifest(expected=original, actual=modified, work=work())

    def test_duplicate_skipped_ordinal_backward_group_and_forbidden_rank_poison_owner(self):
        for kind in ("duplicate", "skip", "backward", "rank", "body"):
            with self.subTest(kind=kind):
                owner = manifest.MaintenanceManifest(context=context(), work=work())
                owner.append(phase_ordinal=0, kind="primary", index_id="",
                    ordinal=0, body_bytes=b"one", work=work())
                fields = dict(phase_ordinal=0, kind="primary", index_id="", ordinal=1, body_bytes=b"two")
                if kind == "duplicate": fields["ordinal"] = 0
                elif kind == "skip": fields["ordinal"] = 2
                elif kind == "backward": fields.update(kind="count", ordinal=0)
                elif kind == "rank": fields.update(kind="rank", ordinal=0)
                else: fields["body_bytes"] = bytearray(b"not exact bytes")
                with self.assertRaises(manifest.ChallengeManifestError):
                    owner.append(**fields, work=work())
                with self.assertRaises(manifest.ChallengeManifestError):
                    owner.finish(work=work())

    def test_full_body_bound_and_source_primary_page_cap_are_preserved(self):
        owner = manifest.MaintenanceManifest(context=context(), work=work())
        body = b"x" * manifest.MAX_BODY_BYTES
        meter = work()
        owner.append(phase_ordinal=0, kind="primary", index_id="", ordinal=0, body_bytes=body, work=meter)
        self.assertGreaterEqual(meter.input_bytes, len(body))
        for ordinal in range(1, 256):
            owner.append(phase_ordinal=0, kind="primary", index_id="", ordinal=ordinal,
                body_bytes=b"x", work=work())
        with self.assertRaises(manifest.ChallengeManifestError):
            owner.append(phase_ordinal=0, kind="primary", index_id="", ordinal=256,
                body_bytes=b"x", work=work())
        with self.assertRaises(manifest.ChallengeManifestError):
            owner.finish(work=work())


if __name__ == "__main__":
    unittest.main()
