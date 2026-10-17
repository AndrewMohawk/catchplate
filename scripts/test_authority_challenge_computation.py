#!/usr/bin/env python3
"""Real empty-root replay/reserve signatures with explicit synthetic originals.

The existing plan fixture uses SQL/clock doubles only. Real source-complete
vectors, raw-page replay, commitments, enrollment and Ed25519 verification are
retained. These controls establish no live PostgreSQL, protected key custody,
grant admission, currentness, reservation or commit authority.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_computation as source
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_challenge_plan import Fixture as PlanFixture


def work(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def frame(domain, *values):
    return digest(domain.encode("ascii") + b"\x00" + b"".join(
        len(value).to_bytes(8, "big") + value for value in values))


def key(seed):
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


class Fixture:
    def __init__(self):
        self.plan = PlanFixture()
        produced = self.plan.produce()
        self.originals = produced.envelope_bytes, produced.request_bytes, produced.manifest_bytes
        self.root, self.computation = key(80), key(81)
        vector, ledger = source.vector, work()
        before, profiles = vector._source_on_work(ledger)
        empty = vector.roots._primary_empty_root(ledger)
        before["primaryRoots"] = [dict(table=table, rootRevision=0, rootDigest=empty, leafCount=0)
            for table in vector.PRIMARY_TABLES]
        before["countedRoots"] = [dict(indexId=name, table=profiles[name].table,
            countedProfile=vector.counted.PROFILE, projectionDigest=profiles[name].projection_digest,
            projectionManifestDigest=before["projectionManifestDigest"], indexRevision=0,
            rootDigest=vector.counted.empty_node(profiles[name], "").digest, leafCount=0)
            for name in vector.INDEX_IDS]
        self.before = vector._encode_on_work(before, work=ledger)
        self.enrollment_payload = dict(schema=source.authorization.ENROLLMENT_PAYLOAD_SCHEMA,
            sourceRevision=source.computation.authority.SOURCE_REVISION, databaseId="synthetic-maintenance-db",
            generationDigest=digest(b"synthetic generation"), initialVector=before,
            maxControlAgeNs=1000, maxClockSkewNs=0, maxRecords=64)
        for role, private in (("computation", self.computation), ("completion", key(82)), ("state", key(83))):
            public = private.public_key()
            self.enrollment_payload[role] = dict(publicKeyPem=public.public_bytes(source.authorization.Encoding.PEM,
                source.authorization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
                spkiDigest=source.evidence.keys._spki_on_work(public, work()),
                measurementDigest=digest(("synthetic " + role).encode()))
        self.seal()

    def seal(self):
        self.enrollment = source.authorization._produce_enrollment_on_work(payload=self.enrollment_payload,
            root_private_key=self.root, root_public_key=self.root.public_key(), work=work())

    def arguments(self, **changes):
        arguments = dict(originals=self.originals, expectations=self.plan.expected,
            planner_public_key=self.plan.public, before_vector_bytes=self.before,
            enrollment_bytes=self.enrollment, root_public_key=self.root.public_key(),
            computation_private_key=self.computation, capability_digest=digest(b"independently held synthetic grant"),
            predecessor_sequence=0, predecessor_head_digest=digest(b"synthetic predecessor"), fence=1,
            live_window=self.plan.window, read_original=self.plan.read, check=lambda stage: None, work=work())
        arguments.update(changes)
        return arguments


class ChallengeComputationControls(unittest.TestCase):
    def setUp(self):
        for name, value in (("monotonic_ns", 10), ("time_ns", 5_000_000_000)):
            patcher = mock.patch.object(source.clock.time, name, return_value=value)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def test_actual_raw_replay_and_root_enrolled_reserve_bind_all_originals(self):
        fixture, meter = Fixture(), work()
        result = source.produce_reserve(**fixture.arguments(work=meter))
        self.assertIs(type(result), source.computation.CurrentRootComputation)
        self.assertEqual(fixture.plan.reads, list(fixture.plan.bodies))
        snapshot = source.computation._decode_snapshot_on_work(result.snapshot_bytes, work=work())
        _, reserve, _ = source.authorization._verify_request_on_work(request_bytes=result.request_bytes,
            enrollment_bytes=fixture.enrollment, root_public_key=fixture.root.public_key(),
            now_epoch_ns=fixture.plan.epoch, work=work())
        self.assertEqual(snapshot["retainedRecordDigest"], frame(source.ORIGINAL_RECORD_DOMAIN, *fixture.originals))
        self.assertEqual(snapshot["planDigest"], frame(source.plan.IDENTITY_DOMAIN, fixture.originals[0]))
        self.assertEqual(snapshot["originalFrames"], [dict(position=index, bytesDigest=digest(raw), byteCount=len(raw))
            for index, raw in enumerate(fixture.originals)])
        self.assertEqual(snapshot["beforeVectorDigest"], snapshot["afterVectorDigest"])
        self.assertEqual(snapshot["beforeVectorDigest"], frame(source.vector.IDENTITY_DOMAIN, fixture.before))
        self.assertEqual((reserve["issuedAtEpochNs"], reserve["expiresAtEpochNs"]),
            (snapshot["originalIssuedAtEpochNs"], snapshot["originalExpiresAtEpochNs"]))
        self.assertEqual(reserve["capabilityDigest"], fixture.arguments()["capability_digest"])
        self.assertEqual(reserve["snapshotDigest"], frame(source.computation.SNAPSHOT_DOMAIN, result.snapshot_bytes))
        self.assertEqual(reserve["beforeVector"], reserve["afterVector"])
        self.assertIsNone(snapshot["signedSnapshotDigest"])
        self.assertIsNone(snapshot["signedCapabilityId"])
        self.assertGreater(meter.hash_work, 0)

    def test_later_narrower_receiver_preserves_exact_parent_issue_and_expiry(self):
        fixture = Fixture()
        epoch = fixture.plan.epoch
        receiver = (epoch + 100, 110, 110, epoch + 800, 810, 1000, 0)
        self.time_ns.return_value, self.monotonic_ns.return_value = epoch + 100, 110
        produced = source.produce_reserve(**fixture.arguments(live_window=receiver))
        payload = json.loads(produced.request_bytes)["payload"]
        self.assertEqual((payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]),
            (epoch, epoch + 990))
        self.assertGreater(payload["expiresAtEpochNs"], receiver[3])
        self.assertEqual(fixture.plan.reads, list(fixture.plan.bodies))

    def test_exact_original_interval_must_fit_enrollment_without_rewriting(self):
        fixture = Fixture()
        fixture.enrollment_payload["maxControlAgeNs"] = 500
        fixture.seal()
        with mock.patch.object(source.authorization, "_produce_request_on_work",
                side_effect=AssertionError("shortened interval signed")):
            with self.assertRaises(ValueError):
                source.produce_reserve(**fixture.arguments())
        self.assertEqual(fixture.plan.reads, [])

    def test_wrong_signer_or_tampered_raw_pages_never_reach_reserve_signing(self):
        for change in ("signer", "page", "before"):
            fixture, options = Fixture(), {}
            if change == "signer":
                options["computation_private_key"] = key(90)
            elif change == "page":
                fixture.plan.bodies[next(iter(fixture.plan.bodies))] += b"\n"
            else:
                before = json.loads(fixture.before)
                before["primaryRoots"] = before["primaryRoots"][:-1]
                options["before_vector_bytes"] = source.evidence.plan.core.canonical_bytes(before)
            with self.subTest(change=change), mock.patch.object(source.authorization, "_produce_request_on_work",
                    side_effect=AssertionError("unverified replay signed")):
                with self.assertRaises(ValueError):
                    source.produce_reserve(**fixture.arguments(**options))

    def test_callback_expiry_cancellation_and_parent_meter_replacement_refuse(self):
        for failure in ("expiry", "cancel", "reset"):
            fixture, meter = Fixture(), work()
            cancellation = KeyboardInterrupt()
            def check(stage):
                if failure == "expiry":
                    self.monotonic_ns.return_value = 1000
                    self.time_ns.return_value = fixture.plan.epoch + 990
                elif failure == "cancel":
                    raise cancellation
                else:
                    meter.input_bytes = 0
            with self.subTest(failure=failure), mock.patch.object(source.authorization, "_produce_request_on_work",
                    side_effect=AssertionError("failed replay signed")):
                with self.assertRaises(KeyboardInterrupt if failure == "cancel" else ValueError) as caught:
                    source.produce_reserve(**fixture.arguments(check=check, work=meter))
                if failure == "cancel":
                    self.assertIs(caught.exception, cancellation)
            self.monotonic_ns.return_value, self.time_ns.return_value = 10, 5_000_000_000

    def test_snapshot_only_branch_does_not_admit_generic_replay_or_oversize_frames(self):
        fixture = Fixture()
        produced = source.produce_reserve(**fixture.arguments())
        snapshot = json.loads(produced.snapshot_bytes)
        self.assertNotIn(source.OPERATION, source.computation.replay.OPERATIONS)
        with self.assertRaises(ValueError):
            source.computation.replay._frame_maxima(source.OPERATION)
        for index, maximum in enumerate(source.FRAME_MAXIMA):
            changed = copy.deepcopy(snapshot)
            changed["originalFrames"][index]["byteCount"] = maximum + 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                source.computation._snapshot_shape(changed)
        self.assertNotIn("observed", inspect.signature(source.produce_reserve).parameters)
        tree = ast.parse(inspect.getsource(source))
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertEqual(calls.count("current_root.replay_to_complete_vector"), 1)
        self.assertIn("authorization._produce_request_on_work", calls)
        self.assertFalse(any(name.rsplit(".", 1)[-1] in {"_open_on_work", "_ValidationWork", "connect", "commit"}
            for name in calls))


if __name__ == "__main__":
    unittest.main()
