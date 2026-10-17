"""Real signed empty-root compositions with explicit SQL/clock doubles.

The shared snapshot fixture bypasses only its native psycopg constructor and
records synthetic SQL rows. Actual request commitments, both source passes,
proofs, manifests, Ed25519 signatures and independent raw replay are retained.
These controls do not establish PostgreSQL, key custody or parent authority.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from cryptography.exceptions import InvalidSignature

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_plan as plan
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_challenge_plan_request import fixture as request_fixture
from test_authority_challenge_snapshot import component_owner


def work():
    return _ValidationWork(QueryReadValidationLimits())


class Fixture:
    def __init__(self, *, check=None):
        self.owner, context = component_owner(check=check)
        request = request_fixture(user_id=context["userId"], scope_key=None, replace_scope=False)
        self.request = plan.evidence.plan.core.canonical_bytes(request)
        context.update(operationId=request["operationId"], requestDigest=request["requestDigest"])
        # Construct the synthetic original before either real source pass;
        # no already-held context/root/proof is replaced during acquisition.
        self.owner._context = plan.manifests._context(context, self.owner._initial)
        self.owner._context_bytes = self.owner._initial.wire(self.owner._context)
        self.private = plan.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.public = self.private.public_key()
        self.epoch = context["cutoffUs"] * 1000
        self.window = (self.epoch, 10, 10, self.epoch + 990, 1000, 1000, 0)
        self.expected = {"context": copy.deepcopy(context),
            "plannerIdentity": {name: "sha256:" + character * 64 for name, character in (
                ("sessionIdentityDigest", "1"), ("measurementDigest", "2"),
                ("attestationReceiptDigest", "3"))},
            "plannerSpkiDigest": plan.evidence.keys._spki_on_work(self.public, work()),
            "policy": dict(nowEpochNs=self.epoch, deadlineEpochNs=self.epoch + 990,
                maximumPlanAgeNs=1000, maximumClockSkewNs=0)}
        self.bodies, self.reads = {}, []

    def retain(self, parent, manifest, context, phase, kind, index, ordinal, raw, descriptor, stage):
        if type(raw) is not bytes or descriptor["byteCount"] != len(raw):
            raise AssertionError("retention did not receive the exact source original")
        stage.work.charge(input_bytes=8)  # Explicit component control cost.
        self.bodies[parent, manifest, phase, kind, index, ordinal] = raw

    def read(self, parent, manifest, phase, kind, index, ordinal, stage):
        key = parent, manifest, phase, kind, index, ordinal
        self.reads.append(key)
        stage.work.charge(input_bytes=8)
        stage.acquisition.transport_bytes += 8  # Not a PG wire-size claim.
        return self.bodies[key]

    def produce(self, *, meter=None, retain=None):
        return plan.produce_maintenance_parent(acquisition=self.owner, request_bytes=self.request,
            expectations=self.expected, planner_private_key=self.private, planner_public_key=self.public,
            live_window=self.window, retain_page=self.retain if retain is None else retain,
            work=work() if meter is None else meter)

    def verify(self, produced, *, meter=None, check=None, envelope=None):
        return plan.verify_maintenance_parent(
            envelope_bytes=produced.envelope_bytes if envelope is None else envelope,
            request_bytes=produced.request_bytes, manifest_bytes=produced.manifest_bytes,
            expectations=self.expected, planner_public_key=self.public, read_original=self.read,
            check=(lambda stage: None) if check is None else check,
            work=work() if meter is None else meter)


class ChallengePlanControls(unittest.TestCase):
    def setUp(self):
        for name, value in (("monotonic_ns", 10), ("time_ns", 5_000_000_000)):
            patcher = mock.patch.object(plan.clock.time, name, return_value=value)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def test_real_two_pass_signing_and_independent_replay_close_exact_originals(self):
        fixture = Fixture()
        meter = work()
        produced = fixture.produce(meter=meter)
        self.assertEqual(tuple(item.pass_ordinal for item in produced.acquisition_metrics.passes), (0, 1))
        self.assertEqual(fixture.owner._state, "retained")
        self.assertEqual(len(fixture.bodies), 9)
        before = meter.metrics
        verified = fixture.verify(produced, meter=meter)
        self.assertEqual((verified.envelope_bytes, verified.request_bytes, verified.manifest_bytes,
            verified.plan_digest), (produced.envelope_bytes, produced.request_bytes,
            produced.manifest_bytes, produced.plan_digest))
        self.assertEqual(fixture.reads, list(fixture.bodies))
        self.assertEqual(verified.replay.observation.decision.primary_after.leaf_count, 0)
        self.assertEqual(verified.replay.total_acquisition.sql_reads, 0)
        self.assertEqual(verified.replay.total_acquisition.transport_bytes,
            sum(len(raw) + 8 for raw in fixture.bodies.values()))
        self.assertGreater(meter.input_bytes, before.input_bytes)
        self.assertEqual(fixture.owner._cursor.closes, 0)

    def test_first_pass_callback_cannot_reset_parent_allowance(self):
        meter = work()
        def reset():
            meter.input_bytes = 0
        fixture = Fixture(check=reset)
        with self.assertRaises(ValueError):
            fixture.produce(meter=meter)
        self.assertTrue(fixture.owner._closed)
        self.assertEqual(fixture.bodies, {})

    def test_second_pass_cannot_reset_or_replace_parent_allowance(self):
        for alter in (lambda meter: setattr(meter, "input_bytes", 0),
                lambda meter: setattr(meter, "limits", QueryReadValidationLimits())):
            with self.subTest(alter=alter):
                fixture, meter = Fixture(), work()
                def retain(*arguments):
                    fixture.retain(*arguments)
                    alter(meter)
                with self.assertRaises(ValueError):
                    fixture.produce(meter=meter, retain=retain)
                self.assertTrue(fixture.owner._closed)
                self.assertTrue(fixture.bodies)  # Partial custody is not a returned plan.
                self.assertEqual(fixture.owner._cursor.closes, 0)

    def test_replay_callback_cannot_change_parent_allowance(self):
        for alter in (lambda meter: setattr(meter, "input_bytes", 0),
                lambda meter: setattr(meter, "limits", QueryReadValidationLimits())):
            with self.subTest(alter=alter):
                fixture = Fixture()
                produced, meter = fixture.produce(), work()
                def check(stage):
                    alter(meter)
                with self.assertRaises(ValueError):
                    fixture.verify(produced, meter=meter, check=check)
                self.assertTrue(fixture.reads)

    def test_signature_and_actual_retained_bytes_cannot_substitute_for_each_other(self):
        fixture = Fixture()
        produced = fixture.produce()
        changed = json.loads(produced.envelope_bytes)
        changed["payload"]["decision"]["pruningPending"] = True
        with self.assertRaises(InvalidSignature):
            fixture.verify(produced, envelope=plan.evidence.plan.core.canonical_bytes(changed))
        self.assertEqual(fixture.reads, [])
        first = next(iter(fixture.bodies))
        fixture.bodies[first] += b"\n"
        with self.assertRaises(ValueError):
            fixture.verify(produced)
        self.assertEqual(fixture.reads, [first])

    def test_retention_verdict_or_original_deadline_expiry_cannot_release_parent(self):
        fixture = Fixture()
        with self.assertRaises(ValueError):
            fixture.produce(retain=lambda *args: True)
        self.assertTrue(fixture.owner._closed)
        fixture = Fixture()
        def expire(*arguments):
            fixture.retain(*arguments)
            self.monotonic_ns.return_value = fixture.owner._original_deadline
        with self.assertRaises(ValueError):
            fixture.produce(retain=expire)
        self.assertTrue(fixture.owner._closed)
        self.assertEqual(fixture.owner._cursor.closes, 0)


if __name__ == "__main__":
    unittest.main()
