#!/usr/bin/env python3
"""Synthetic signed controls plus genuine empty-root/raw-page stream replay.

The reused planner fixture explicitly doubles native SQL and clocks. Root,
authorizer, computation and state signatures are actual Ed25519; all raw-page
proofs and the complete vector are genuinely recomputed. Tentative effects are
captured in memory only. This is not PostgreSQL custody/execution, a current
checkpoint admission, nonempty-row coverage, or a successful deployment test.
"""
from __future__ import annotations

import ast
import base64
import copy
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_challenge_execution_packet as packet
from test_authority_challenge_computation import Fixture as ComputationFixture, digest, frame, key, work


source = packet.admission


def raw_frame(value):
    raw = base64.urlsafe_b64decode(value["base64Url"] + "=" * (-len(value["base64Url"]) % 4))
    if value["bytesDigest"] != digest(raw) or value["byteCount"] != len(raw):
        raise AssertionError("retained original framing changed")
    return raw


class Fixture:
    def __init__(self):
        self.base = base = ComputationFixture()
        self.authorizer = key(84)
        self.authorization_digest = digest(b"independently held synthetic request authorization")
        self.delegation = source.grants.produce_enrollment(
            current_root_enrollment_bytes=base.enrollment, root_private_key=base.root,
            root_public_key=base.root.public_key(), authorizer_public_key=self.authorizer.public_key(),
            authorizer_measurement_digest=digest(b"synthetic authorizer"),
            maximum_grant_age_ns=1000, maximum_clock_skew_ns=0, work=work())
        self.grant = source.grants.produce_grant(originals=base.originals,
            expectations=base.plan.expected, planner_public_key=base.plan.public,
            before_vector_bytes=base.before, grant_enrollment_bytes=self.delegation,
            current_root_enrollment_bytes=base.enrollment, root_public_key=base.root.public_key(),
            authorizer_private_key=self.authorizer, expected_authorization_digest=self.authorization_digest,
            live_window=base.plan.window, read_original=base.plan.read, check=lambda stage: None, work=work())
        self.grant_digest = frame(source.grants.GRANT_IDENTITY_DOMAIN, self.grant)
        produced = source.computation.produce_reserve(**base.arguments(capability_digest=self.grant_digest))
        self.reserve, self.snapshot = produced.request_bytes, produced.snapshot_bytes
        material, reserve, request_digest = source.authorization._verify_request_on_work(
            request_bytes=self.reserve, enrollment_bytes=base.enrollment, root_public_key=base.root.public_key(),
            now_epoch_ns=base.plan.epoch, work=work())
        snap = json.loads(self.snapshot)
        receipt = dict(schema=source.authorization.RECEIPT_PAYLOAD_SCHEMA,
            sourceRevision=source.authorization.authority.SOURCE_REVISION, action="reserve",
            enrollmentDigest=material.enrollment_digest, databaseId=material.payload["databaseId"],
            generationDigest=material.payload["generationDigest"],
            producerMeasurementDigest=material.payload["state"]["measurementDigest"],
            requestDigest=request_digest, pendingRequestDigest=request_digest,
            sequence=1, previousHeadDigest=reserve["predecessorHeadDigest"], fence=1,
            beforeVectorDigest=snap["beforeVectorDigest"], afterVectorDigest=snap["afterVectorDigest"],
            issuedAtEpochNs=reserve["issuedAtEpochNs"], expiresAtEpochNs=reserve["expiresAtEpochNs"])
        self.receipt = source.authorization._produce_receipt_on_work(payload=receipt,
            enrollment_bytes=base.enrollment, root_public_key=base.root.public_key(),
            state_private_key=key(83), work=work())
        self.pending_digest = source.authorization._receipt_digest_on_work(self.receipt, work())
        self.effects = []
        base.plan.reads.clear()

    def retain(self, ordinal, raw, descriptor, stage):
        self.effects.append((ordinal, raw, copy.deepcopy(descriptor)))
        stage.work.charge(input_bytes=8)  # Explicit in-memory component overhead only.

    def arguments(self, **changes):
        base = self.base
        arguments = dict(originals=base.originals, expectations=base.plan.expected,
            planner_public_key=base.plan.public, enrollment_bytes=base.enrollment,
            root_public_key=base.root.public_key(), reserve_request_bytes=self.reserve,
            reserve_receipt_bytes=self.receipt, snapshot_bytes=self.snapshot,
            grant_bytes=self.grant, grant_enrollment_bytes=self.delegation,
            expected_authorization_digest=self.authorization_digest,
            expected_database_id=base.enrollment_payload["databaseId"],
            expected_generation_digest=base.enrollment_payload["generationDigest"],
            expected_pending_sequence=1, expected_pending_head_digest=self.pending_digest,
            expected_fence=1, live_window=base.plan.window, read_original=base.plan.read,
            check=lambda stage: None, retain_effect=self.retain, work=work())
        arguments.update(changes)
        return arguments


class ChallengeExecutionAdmissionControls(unittest.TestCase):
    def setUp(self):
        for name, value in (("monotonic_ns", 10), ("time_ns", 5_000_000_000)):
            patcher = mock.patch.object(source.grants.clock.time, name, return_value=value)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def test_real_raw_replay_controls_and_all_six_empty_phases_bind_packet(self):
        fixture = Fixture()
        prepared = packet._prepare_on_work(**fixture.arguments())
        value = json.loads(prepared.packet_bytes)
        self.assertEqual(prepared.packet_digest, frame(packet.IDENTITY_DOMAIN, prepared.packet_bytes))
        self.assertEqual(fixture.base.plan.reads, list(fixture.base.plan.bodies))
        self.assertEqual(set(value), packet.FIELDS)
        self.assertNotIn("mutations", value)
        self.assertNotIn("selectedRows", value)
        self.assertEqual(value["grantDigest"], fixture.grant_digest)
        self.assertEqual(value["pendingDecisionDigest"], fixture.pending_digest)
        self.assertEqual(value["marker"]["capability_digest"], fixture.grant_digest)
        self.assertEqual(value["marker"]["pending_decision_digest"], fixture.pending_digest)
        self.assertEqual(raw_frame(value["beforeVector"]), fixture.base.before)
        self.assertEqual(raw_frame(value["afterVector"]), fixture.base.before)
        header_raw = raw_frame(value["streamHeader"])
        header = json.loads(header_raw)
        self.assertEqual(value["streamDigest"], frame(source.streams.IDENTITY_DOMAIN, header_raw))
        self.assertEqual(header["stepCount"], 12)
        self.assertEqual(header["steps"], [descriptor for _n, _raw, descriptor in fixture.effects])
        self.assertEqual([(row["kind"], row["phaseOrdinal"]) for row in header["steps"]],
            [(kind, phase) for phase in (0, 1, 2, 4, 5, 6) for kind in ("phase-before", "phase-after")])
        self.assertEqual([raw_frame(item) for item in value["originals"]["plan"]], list(fixture.base.originals))

    def test_independent_pending_authorization_and_signed_control_refuse_before_effects(self):
        for changed in ({"expected_pending_head_digest": digest(b"wrong pending")},
                {"expected_fence": 2}, {"expected_authorization_digest": digest(b"wrong authorization")},
                {"grant_bytes": b"{}"}, {"reserve_receipt_bytes": b"{}"}):
            fixture = Fixture()
            with self.subTest(changed=tuple(changed)), self.assertRaises(ValueError):
                packet._prepare_on_work(**fixture.arguments(**changed))
            self.assertEqual(fixture.effects, [])

    def test_raw_page_or_snapshot_corruption_never_returns_sealed_header(self):
        for changed in ("page", "snapshot"):
            fixture, arguments = Fixture(), {}
            if changed == "page":
                fixture.base.plan.bodies[next(iter(fixture.base.plan.bodies))] += b"\n"
            else:
                arguments["snapshot_bytes"] = fixture.snapshot + b"\n"
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                packet._prepare_on_work(**fixture.arguments(**arguments))
            if changed == "snapshot":
                self.assertTrue(fixture.effects)  # Tentative prefix is not executable custody.

    def test_effect_callback_cannot_change_descriptor_parent_work_or_return_verdict(self):
        for changed in ("descriptor", "parent", "verdict"):
            fixture, meter = Fixture(), work()
            def retain(*args):
                fixture.retain(*args)
                if changed == "descriptor":
                    args[2]["digest"] = digest(b"changed descriptor")
                elif changed == "parent":
                    meter.input_bytes = 0
                else:
                    return True
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                packet._prepare_on_work(**fixture.arguments(retain_effect=retain, work=meter))

    def test_original_expiry_and_base_exception_prevent_output(self):
        fixture = Fixture()
        self.time_ns.return_value = fixture.base.plan.epoch + 990
        self.monotonic_ns.return_value = 1000
        with self.assertRaises(ValueError):
            packet._prepare_on_work(**fixture.arguments())
        self.assertEqual(fixture.effects, [])
        self.time_ns.return_value, self.monotonic_ns.return_value = fixture.base.plan.epoch, 10
        failure = KeyboardInterrupt()
        def cancelled(*args):
            raise failure
        with self.assertRaises(KeyboardInterrupt) as caught:
            packet._prepare_on_work(**fixture.arguments(retain_effect=cancelled))
        self.assertIs(caught.exception, failure)

    def test_public_path_accepts_only_originals_and_real_stream_admission(self):
        self.assertNotIn("derived", inspect.signature(packet._prepare_on_work).parameters)
        self.assertNotIn("observation", inspect.signature(source._prepare_on_work).parameters)
        tree = ast.parse(inspect.getsource(source))
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertEqual(calls.count("streams.derive_stream"), 1)
        for expected in ("authorization._verify_request_on_work", "authorization._verify_receipt_on_work",
                "grants._verify_control_on_work", "pending._pending", "computation._snapshot_on_work"):
            self.assertIn(expected, calls)
        self.assertFalse(any(name.rsplit(".", 1)[-1] in {"_open_on_work", "connect", "commit", "_ValidationWork"}
            for name in calls))


if __name__ == "__main__":
    unittest.main()
