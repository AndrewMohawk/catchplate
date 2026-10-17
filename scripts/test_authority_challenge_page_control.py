"""Pure canonical control-codec controls; no transport/SQL/parent admission."""
from __future__ import annotations

import ast
import copy
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_page_control as control
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_challenge_manifest import context


def work(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def arguments(action="read", **changes):
    result = dict(action=action, parent_plan_digest="sha256:" + "1" * 64,
        maintenance_manifest_digest="sha256:" + "2" * 64, context=context(),
        phase_ordinal=0, page_kind="count", index_id="", page_ordinal=0,
        descriptor=None if action == "read" else {"digest": "sha256:" + "3" * 64, "byteCount": 123})
    result.update(changes)
    return result


def canonical(value, *, ascii=True):
    return json.dumps(value, ensure_ascii=ascii, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encode(values=None, *, meter=None):
    return control.encode_control(**(arguments() if values is None else values),
        work=work() if meter is None else meter)


class ChallengePageControlControls(unittest.TestCase):
    def test_exact_ascii_owned_roundtrip_for_both_actions_and_all_six_kinds(self):
        cases = ((0, "count", "", 0), (3, "range", "", 0), (2, "rank", "", 0),
            (4, "primary", "", 255), (6, "write", control.binding.store.INDEX_IDS[0], 5120),
            (5, "candidate", "", 24))
        with mock.patch.object(control.binding.time, "monotonic_ns", side_effect=AssertionError("clock sampled")):
            for action in ("persist", "read"):
                for phase, kind, index, ordinal in cases:
                    with self.subTest(action=action, kind=kind):
                        values = arguments(action, phase_ordinal=phase, page_kind=kind,
                            index_id=index, page_ordinal=ordinal)
                        expected = copy.deepcopy(values)
                        meter = work()
                        raw = encode(values, meter=meter)
                        self.assertTrue(raw.isascii())
                        self.assertLessEqual(len(raw), control.MAX_CONTROL_BYTES)
                        before = meter.metrics
                        decoded = control.decode_control(raw, expected_action=action, work=meter)
                        self.assertEqual(set(decoded), control.FIELDS)
                        self.assertEqual(raw, canonical(decoded))
                        self.assertEqual(decoded["context"], expected["context"])
                        self.assertEqual(decoded["descriptor"], expected["descriptor"])
                        self.assertEqual((decoded["phaseOrdinal"], decoded["pageKind"],
                            decoded["indexId"], decoded["pageOrdinal"]), (phase, kind, index, ordinal))
                        self.assertGreater(meter.input_bytes, before.input_bytes)
                        values["context"]["indexHeads"].clear()
                        self.assertEqual(decoded["context"], expected["context"])
                        if action == "persist":
                            values["descriptor"]["byteCount"] = 999
                            self.assertEqual(decoded["descriptor"], expected["descriptor"])

    def test_closed_fields_schema_action_and_detached_descriptor_direction(self):
        raw = encode()
        original = json.loads(raw)
        for field in original:
            changed = copy.deepcopy(original)
            del changed[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                control.decode_control(canonical(changed), expected_action="read", work=work())
        for field, value in (("schema", "other"), ("action", "persist"), ("action", True),
                ("accepted", True), ("originalDeadlineNs", 1000), ("descriptor", {})):
            changed = {**original, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                control.decode_control(canonical(changed), expected_action="read", work=work())
        for expected in ("persist", True, "READ", None):
            with self.assertRaises(ValueError):
                control.decode_control(raw, expected_action=expected, work=work())
        for values in (arguments("persist", descriptor=None), arguments("read", descriptor={}),
                arguments(True), arguments("other")):
            with self.assertRaises(ValueError):
                encode(values)

    def test_actual_parent_context_and_source_store_coordinates_are_required(self):
        for changes in (dict(parent_plan_digest="other"), dict(maintenance_manifest_digest=True),
                dict(phase_ordinal=True), dict(phase_ordinal=8), dict(page_ordinal=True),
                dict(page_kind="candidate", page_ordinal=25), dict(page_kind="rank", phase_ordinal=0),
                dict(page_kind="write", phase_ordinal=3, index_id=control.binding.store.INDEX_IDS[0]),
                dict(page_kind="primary", phase_ordinal=7), dict(index_id="caller-table")):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                encode(arguments(**changes))
        for name, value in (("sourceRevision", "old"), ("operation", "webauthn.challenge.claim"),
                ("originalDeadlineNs", True), ("originalDeadlineNs", 0), ("accepted", True),
                ("primaryRoot", {}), ("indexHeads", [])):
            values = arguments()
            values["context"][name] = value
            with self.subTest(context_field=name), self.assertRaises(ValueError):
                encode(values)

    def test_persist_descriptor_has_exact_framing_only_and_no_success_fields(self):
        for count in (1, control.transport.MAX_BODY_BYTES):
            values = arguments("persist", descriptor={"digest": "sha256:" + "a" * 64, "byteCount": count})
            decoded = control.decode_control(encode(values), expected_action="persist", work=work())
            self.assertEqual(decoded["descriptor"], values["descriptor"])
        for record in ({"digest": "other", "byteCount": 1}, {"digest": "sha256:" + "a" * 64, "byteCount": True},
                {"digest": "sha256:" + "a" * 64, "byteCount": 0},
                {"digest": "sha256:" + "a" * 64, "byteCount": control.transport.MAX_BODY_BYTES + 1},
                {"digest": "sha256:" + "a" * 64},
                {"digest": "sha256:" + "a" * 64, "byteCount": 1, "accepted": True}):
            with self.subTest(record=record), self.assertRaises(ValueError):
                encode(arguments("persist", descriptor=record))

    def test_original_canonical_ascii_bytes_and_preallocation_bound(self):
        values = arguments()
        values["context"]["userId"] = "caf\u00e9"
        raw = encode(values)
        malformed = (raw + b"\n", b'{"action":"read",' + raw[1:], bytearray(raw),
            canonical(json.loads(raw), ascii=False), raw.replace(b'"phaseOrdinal":0', b'"phaseOrdinal":0.0'),
            b"{" + b" " * control.MAX_CONTROL_BYTES + b"}", b"[]")
        for changed in malformed:
            with self.subTest(kind=type(changed).__name__), self.assertRaises(ValueError):
                control.decode_control(changed, expected_action="read", work=work())
        for text in ("\x00", "\ud800", "x" * control.MAX_CONTROL_BYTES):
            oversized = arguments()
            oversized["context"]["userId"] = text
            with self.assertRaises(ValueError):
                encode(oversized)

    def test_shared_budget_is_not_replaced_and_source_has_no_authority_or_io(self):
        raw = encode()
        for limits in (dict(max_input_bytes=128), dict(max_json_nodes=8), dict(max_hashes=1)):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                encode(meter=work(**limits))
            with self.subTest(decode_limits=limits), self.assertRaises(ValueError):
                control.decode_control(raw, expected_action="read", work=work(**limits))
        for bad in (None, object()):
            with self.assertRaises(ValueError):
                control.decode_control(raw, expected_action="read", work=bad)
        tree = ast.parse(inspect.getsource(control))
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        for actual in ("binding._prepare", "binding.store._binding", "wire._decode_object",
                "wire.plan.retained._bounded_wire", "transport._lengths"):
            self.assertIn(actual, calls)
        self.assertFalse(any(name.rsplit(".", 1)[-1] in {"connect", "execute", "commit", "rollback",
            "monotonic_ns", "time_ns", "persist_page", "read_original", "_socket_exchange",
            "_ValidationWork", "verify", "sign"} for name in calls))


if __name__ == "__main__":
    unittest.main()
