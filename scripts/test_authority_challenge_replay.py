"""Genuine empty-root retained proof replay, not SQL or parent admission.

Raw count frontiers and expected compact commitments are synthetic originals
under independently constructed genuine empty roots. No proof engine, chain,
pass, source schedule or ledger is doubled; raw callbacks represent retained
storage only. Nonempty mutations/SQL effects require separate integration.
"""
from __future__ import annotations

import copy
import json
import unittest
from unittest import mock

from catchplate import authority_challenge_counts as counts
from catchplate import authority_challenge_replay as replay
from test_authority_challenge_manifest import context


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class Fixture:
    def __init__(self):
        self.context = context()
        self.context["originalDeadlineNs"] = 1000
        work = replay._ValidationWork(replay.QueryReadValidationLimits())
        heads = {head["indexId"]: head for head in self.context["indexHeads"]}
        self.bodies, self.reads, self.mutations = {}, [], []
        manifest = replay.manifests.MaintenanceManifest(context=self.context, work=work)
        for phase in (0, 1, 2, 4, 5, 6, 7):
            roles = (("expired_remaining", "old_remaining", "admission_terminal_count")
                if phase == 7 else (("expired_remaining", "old_remaining", "admission_terminal_count")[phase % 4],))
            for ordinal, role in enumerate(roles):
                profile, interval = counts.source_interval(role, user_id=self.context["userId"],
                    cutoff_us=self.context["cutoffUs"], rate_window_us=1,
                    retention_us=self.context["retentionUs"], work=work)
                head = heads[profile.index_id]
                raw = canonical({"schema": counts.SCHEMA, "role": role,
                    "indexId": profile.index_id, "indexRevision": head["indexRevision"],
                    "rootDigest": head["rootDigest"], "rootCount": 0,
                    "lower": interval.lower, "upper": interval.upper, "frontier": []})
                self.bodies[phase, "count", "", ordinal] = raw
                manifest.append(phase_ordinal=phase, kind="count", index_id="",
                    ordinal=ordinal, body_bytes=raw, work=work)
        self.manifest = manifest.finish(work=work)

    def read(self, phase, kind, index_id, ordinal, stage):
        self.reads.append((phase, kind, index_id, ordinal))
        # Explicit component control-frame accounting, not a SQL query or
        # PostgreSQL wire-size claim. The owner additionally charges raw bytes.
        stage.work.charge(input_bytes=8)
        stage.acquisition.transport_bytes += 8
        return self.bodies[phase, kind, index_id, ordinal]

    def owner(self, *, expected=None, read=None, check=None):
        return replay._Replay(context=self.context,
            expected_manifest=self.manifest if expected is None else expected,
            read_original=self.read if read is None else read,
            check=(lambda stage: None) if check is None else check,
            apply_mutation=lambda mutation, stage: self.mutations.append(mutation))


class ChallengeReplayTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(replay.time, "monotonic_ns", return_value=10)
        self.clock = patch.start()
        self.addCleanup(patch.stop)
        self.fixture = Fixture()

    def poisoned(self, owner):
        with self.assertRaises(replay.ChallengeReplayError):
            owner.run()

    def test_actual_raw_replay_matches_parent_commitments_and_accounts_one_source_pass(self):
        fixture = self.fixture
        owner = fixture.owner()
        expected = copy.deepcopy(fixture.manifest)
        fixture.context["userId"] = "later caller-owned change"
        fixture.manifest["groups"].clear()
        result = owner.run()
        self.assertEqual(result.observation.manifest, expected)
        self.assertFalse(result.observation.decision.pruning_pending)
        self.assertFalse(result.observation.decision.replacement_overflow)
        self.assertEqual(result.observation.decision.primary_after.leaf_count, 0)
        self.assertEqual(fixture.reads, list(fixture.bodies))
        self.assertEqual(fixture.mutations, [])
        self.assertEqual(result.total_acquisition.sql_reads, 0)
        self.assertEqual(result.total_acquisition.returned_rows, 0)
        self.assertEqual(result.total_acquisition.transport_bytes,
            sum(len(raw) + 8 for raw in fixture.bodies.values()))
        for name in ("hash_work", "input_bytes", "json_nodes"):
            self.assertEqual(getattr(result.total_work, name),
                getattr(result.initial_work, name) + getattr(result.observation.metrics.total_work, name))
        self.assertGreater(result.initial_work.input_bytes, 0)
        self.poisoned(owner)

    def test_parent_context_mismatch_fails_before_raw_callback(self):
        changed = copy.deepcopy(self.fixture.manifest)
        changed["context"]["configurationDigest"] = "sha256:" + "d" * 64
        with self.assertRaises(ValueError):
            self.fixture.owner(expected=changed)
        self.assertEqual(self.fixture.reads, [])
        with self.assertRaises(replay.ChallengeReplayError):
            replay.replay_maintenance(context=self.fixture.context, expected_manifest=self.fixture.manifest,
                read_original=None, check=lambda stage: None)

    def test_changed_noncanonical_wrong_type_or_missing_raw_originals_cannot_become_proofs(self):
        for changed in (lambda raw: raw + b"\n", lambda raw: bytearray(raw),
                lambda raw: canonical({**json.loads(raw), "rootDigest": "sha256:" + "e" * 64})):
            with self.subTest(changed=changed):
                fixture = Fixture()
                first = next(iter(fixture.bodies))
                fixture.bodies[first] = changed(fixture.bodies[first])
                owner = fixture.owner()
                with self.assertRaises(ValueError):
                    owner.run()
                self.poisoned(owner)
        fixture = Fixture()
        del fixture.bodies[next(iter(fixture.bodies))]
        owner = fixture.owner()
        with self.assertRaises(KeyError):
            owner.run()
        self.poisoned(owner)

    def test_full_genuine_replay_precedes_final_whole_manifest_comparison(self):
        changed = copy.deepcopy(self.fixture.manifest)
        changed["groups"][0]["chainDigest"] = "sha256:" + "e" * 64
        owner = self.fixture.owner(expected=changed)
        with self.assertRaises(ValueError):
            owner.run()
        self.assertEqual(self.fixture.reads, list(self.fixture.bodies))
        self.assertTrue(owner._chain._closed)
        self.poisoned(owner)

    def test_original_work_acquisition_and_deadline_cannot_be_replaced_or_reset(self):
        def replace_work(stage):
            stage.work = replay._ValidationWork(replay.QueryReadValidationLimits())
        def replace_limits(stage):
            stage.acquisition.limits = replay.reader._ReadAcquisitionLimits()
        def reset_work(stage):
            stage.work.input_bytes = 0
        def enlarge_transport(stage):
            stage.acquisition.transport_bytes = replay.reader.MAX_TRANSPORT_BYTES
        for change in (replace_work, replace_limits, reset_work, enlarge_transport):
            with self.subTest(change=change):
                fixture = Fixture()
                def changed_read(*arguments):
                    raw = fixture.read(*arguments)
                    change(arguments[-1])
                    return raw
                owner = fixture.owner(read=changed_read)
                with self.assertRaises(ValueError):
                    owner.run()
                self.poisoned(owner)
        owner = self.fixture.owner()
        self.clock.return_value = 1000
        with self.assertRaises(replay.ChallengeReplayError):
            owner.run()
        self.assertEqual(self.fixture.reads, [])

    def test_callback_verdict_reentry_cancellation_and_sql_fallback_poison_owner(self):
        owner = self.fixture.owner(check=lambda stage: True)
        with self.assertRaises(replay.ChallengeReplayError):
            owner.run()
        self.poisoned(owner)
        holder = {}
        def reenter(stage):
            with self.assertRaises(replay.ChallengeReplayError):
                holder["owner"].run()
        owner = self.fixture.owner(check=reenter)
        holder["owner"] = owner
        with self.assertRaises(replay.ChallengeReplayError):
            owner.run()
        self.poisoned(owner)
        cancellation = KeyboardInterrupt()
        def cancel(*args):
            raise cancellation
        owner = self.fixture.owner(read=cancel)
        with self.assertRaises(KeyboardInterrupt) as caught:
            owner.run()
        self.assertIs(caught.exception, cancellation)
        self.poisoned(owner)
        def attempted_sql(*arguments):
            arguments[-1]._cursor.execute("not executed", ())
        owner = self.fixture.owner(read=attempted_sql)
        with self.assertRaises(replay.ChallengeReplayError):
            owner.run()
        self.poisoned(owner)


if __name__ == "__main__":
    unittest.main()
