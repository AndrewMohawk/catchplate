#!/usr/bin/env python3
"""Schedule/codec/source controls, not complete replay or SQL acceptance."""
import ast
import inspect
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_challenge_execution_stream as stream
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


def work():
    return _ValidationWork(QueryReadValidationLimits())


class ChallengeExecutionStreamControls(unittest.TestCase):
    def test_all_six_empty_phases_need_both_edges(self):
        schedule = stream._Schedule()
        for phase in stream.PHASES:
            schedule.advance("phase-before", phase, 0, 0)
            with self.assertRaises(ValueError):
                schedule.finish()
            schedule.advance("phase-after", phase, 0, 0)
        schedule.finish()
        self.assertEqual(schedule.rows, 0)

    def test_full_source_schedule_keeps1536_rows_and1548_steps(self):
        schedule = stream._Schedule()
        count = 0
        for phase in stream.PHASES:
            schedule.advance("phase-before", phase, 0, 256)
            count += 1
            for ordinal in range(256):
                schedule.advance("row", phase, ordinal, None)
                count += 1
            schedule.advance("phase-after", phase, 0, 256)
            count += 1
        schedule.finish()
        self.assertEqual((schedule.rows, count), (1536, stream.MAX_STEPS))
        with self.assertRaises(ValueError):
            schedule.advance("phase-before", 0, 0, 0)

    def test_missing_reordered_duplicated_alias_or_wrong_count_steps_deny(self):
        for event in (("row", 0, 0, None), ("phase-after", 0, 0, 0),
                ("phase-before", 1, 0, 0), ("phase-before", False, 0, 0),
                ("phase-before", 0, False, 0), ("phase-before", 0, 0, True),
                ("phase-before", 0, 0, 257), ("phase-before", 0, 0, -1)):
            with self.subTest(event=event), self.assertRaises(ValueError):
                stream._Schedule().advance(*event)
        for event in (("row", 0, 1, None), ("row", 0, 0, 1),
                ("phase-after", 0, 0, 1), ("phase-before", 0, 0, 1)):
            schedule = stream._Schedule()
            schedule.advance("phase-before", 0, 0, 1)
            with self.subTest(event=event), self.assertRaises(ValueError):
                schedule.advance(*event)

    def test_phase_codec_requires_exact_closed_canonical_source_count(self):
        value = {"schema": stream.source_pass.PHASE_EFFECT_SCHEMA, "phaseOrdinal": 0,
            "rowCount": 0, "primaryRoot": {}, "indexHeads": []}
        raw = work().wire(value)
        # Synthetic root bodies here are data only; the real replay owns proof
        # validation. This codec does not mistake shape for successful proof.
        self.assertEqual(stream._phase_count(raw, 0, work()), 0)
        for changed in (raw + b"\n", raw.replace(b'"rowCount":0', b'"rowCount":true'),
                raw.replace(b'"rowCount":0', b'"rowCount":257'),
                raw.replace(b'"phaseOrdinal":0', b'"phaseOrdinal":1'), bytearray(raw)):
            with self.assertRaises(ValueError):
                stream._phase_count(changed, 0, work())

    def test_failed_or_closed_collector_cannot_return_a_header_or_reenter(self):
        for active, busy in ((False, False), (True, True), (True, False)):
            collector = stream._Collector("sha256:" + "0" * 64, lambda *args: None)
            collector.active, collector.busy = active, busy
            with self.assertRaises(ValueError):
                collector.observe("phase-before", 0, 0, b"{}", object())
            self.assertTrue(collector.failed)
            collector.active = False
            with self.assertRaises(ValueError):
                collector.finish()

    def test_descriptor_copy_is_charged_before_constructing_the_dictionary(self):
        values = ("row", 0, 0, 2, "sha256:" + "0" * 64)
        meter = _ValidationWork(QueryReadValidationLimits(max_input_bytes=1))
        with mock.patch.object(stream, "dict", create=True) as constructor:
            with self.assertRaises(ValueError):
                stream._descriptor(values, meter)
            constructor.assert_not_called()
        meter = work()
        value = stream._descriptor(values, meter)
        self.assertEqual(value, dict(zip(stream._DESCRIPTOR_FIELDS, values, strict=True)))
        self.assertGreater(meter.input_bytes, 0)
        self.assertGreater(meter.json_nodes, 0)

    def test_public_route_calls_actual_replay_once_and_never_accepts_observation(self):
        parameters = inspect.signature(stream.derive_stream).parameters
        self.assertNotIn("observation", parameters)
        tree = ast.parse(inspect.getsource(stream))
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertEqual(calls.count("current_root.replay_to_complete_vector"), 1)
        self.assertIn("self.retain", calls)
        self.assertIn("stage.check", calls)
        self.assertFalse(any(name.rsplit(".", 1)[-1] in {"connect", "execute", "commit",
            "rollback", "_ValidationWork", "sign", "time_ns", "monotonic_ns"} for name in calls))
        with mock.patch.object(stream.current_root, "replay_to_complete_vector") as replay:
            with self.assertRaises(ValueError):
                stream.derive_stream(envelope_bytes=b"{}", request_bytes=b"{}", manifest_bytes=b"{}",
                    expectations={}, planner_public_key=None, before_vector_bytes=b"{}",
                    read_original=lambda *args: None, check=lambda *args: None,
                    retain_effect=lambda *args: None, work=None)
            replay.assert_not_called()


if __name__ == "__main__":
    unittest.main()
