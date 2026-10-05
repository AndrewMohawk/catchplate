"""Closed JIT page-codec controls; no signature, network or native store."""
from __future__ import annotations

import ast
import copy
import inspect
import unittest
from unittest import mock

from serverware import authority_jit_original_control as control
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_jit_original_pages import binding


def meter():
    return _ValidationWork(QueryReadValidationLimits())


def values(action="persist"):
    original = binding()
    return dict(action=action, context={name: original[name] for name in control.store.CONTEXT_FIELDS},
        original_deadline_ns=1000, descriptor=None if action == "read" else
        {"digest": original["body_digest"], "byteCount": original["body_byte_count"]})


class JitOriginalControlControls(unittest.TestCase):
    def test_both_actions_round_trip_exact_owned_originals(self):
        for action in ("persist", "read"):
            supplied = values(action)
            expected = copy.deepcopy(supplied)
            raw = control.encode_control(**supplied, work=meter())
            supplied["context"]["page_kind"] = "caller"
            observed = control.decode_control(raw, expected_action=action, work=meter())
            self.assertEqual(observed, {"schema": control.SCHEMA, "action": action,
                "context": expected["context"], "originalDeadlineNs": 1000,
                "descriptor": expected["descriptor"]})
            self.assertEqual(control.encode_control(**expected, work=meter()), raw)

    def test_exact_action_shape_and_source_coordinates(self):
        for changed in (dict(action="caller"), dict(original_deadline_ns=True),
                dict(original_deadline_ns=0), dict(descriptor={}),
                dict(descriptor={"digest": "sha256:" + "0" * 64, "byteCount": True}),
                dict(context={**values()["context"], "operation": "jit.decide"}),
                dict(context={**values()["context"], "page_ordinal": 231}),
                dict(context={**values()["context"], "accepted": True})):
            with self.subTest(fields=list(changed)), self.assertRaises(ValueError):
                control.encode_control(**{**values(), **changed}, work=meter())
        with self.assertRaises(ValueError):
            control.encode_control(**{**values("read"), "descriptor": values()["descriptor"]}, work=meter())
        raw = control.encode_control(**values(), work=meter())
        with self.assertRaises(ValueError):
            control.decode_control(raw, expected_action="read", work=meter())

    def test_wire_is_canonical_closed_ascii_with_exact_integer_types(self):
        raw = control.encode_control(**values(), work=meter())
        for changed in (b" " + raw, raw + b"\n", raw.replace(b'"originalDeadlineNs":1000',
                b'"originalDeadlineNs":1e3'), raw.replace(b'"page_ordinal":0', b'"page_ordinal":false'),
                raw.replace(b'"schema":', b'"extra":null,"schema":'),
                raw.replace(b'"action":"persist"', b'"action":"persist","action":"persist"')):
            with self.subTest(raw=changed[:40]), self.assertRaises(ValueError):
                control.decode_control(changed, expected_action="persist", work=meter())
        with self.assertRaises(ValueError):
            control.decode_control(bytearray(raw), expected_action="persist", work=meter())

    def test_actual_body_join_not_descriptor_shape_decides_integrity(self):
        original = control.decode_control(control.encode_control(**values(), work=meter()),
            expected_action="persist", work=meter())
        self.assertIs(control._body(original, b"[]", meter()), b"[]")
        for wrong in (b"{}", b"[] ", bytearray(b"[]")):
            with self.assertRaises(ValueError):
                control._body(original, wrong, meter())
        claimed = {**values(), "descriptor": {"digest": "sha256:" + "0" * 64, "byteCount": 2}}
        encoded = control.encode_control(**claimed, work=meter())
        owned = control.decode_control(encoded, expected_action="persist", work=meter())
        with self.assertRaises(ValueError):
            control._body(owned, b"[]", meter())

    def test_existing_work_bounds_precede_capture_and_no_side_effect_owners_exist(self):
        work = _ValidationWork(QueryReadValidationLimits(max_input_bytes=4095))
        with mock.patch.object(control.wire.batch, "_JSONCapture") as capture:
            with self.assertRaises(ValueError):
                control.encode_control(**values(), work=work)
            capture.assert_not_called()
        tree = ast.parse(inspect.getsource(control))
        calls = [ast.unparse(node.func).rsplit(".", 1)[-1] for node in ast.walk(tree)
            if isinstance(node, ast.Call)]
        self.assertFalse(set(calls) & {"connect", "persist_page", "read_original", "sign", "_ValidationWork"})


if __name__ == "__main__":
    unittest.main()
