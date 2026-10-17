"""Pure binding/guard controls and the real-store source join, not PG success.

The local action fixture exercises only this helper's byte/ownership guard.
No admitted connection, successful INSERT/SELECT or proof replay is simulated.
Public entrypoints additionally exercise the real store's refusal of a plain
object connection; native custody remains a separate integration requirement.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import inspect
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_page_binding as binding
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_challenge_manifest import context


def work():
    return _ValidationWork(QueryReadValidationLimits())


def arguments(**changes):
    selected = context()
    selected["originalDeadlineNs"] = 1000
    result = dict(parent_plan_digest="sha256:" + "1" * 64,
        maintenance_manifest_digest="sha256:" + "2" * 64, context=selected,
        phase_ordinal=0, page_kind="count", index_id="", page_ordinal=0,
        original_deadline_ns=1000, work=work())
    result.update(changes)
    return result


def descriptor(raw):
    return {"digest": "sha256:" + hashlib.sha256(raw).hexdigest(), "byteCount": len(raw)}


class ChallengePageBindingControls(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(binding.time, "monotonic_ns", return_value=10)
        self.clock = patcher.start()
        self.addCleanup(patcher.stop)

    def call(self, *, values=None, action=None, check=None, original=None):
        selected = arguments() if values is None else values
        owned, keys = binding._prepare(**selected)
        def local_action(guard):
            guard()
            return b"{}"
        return binding._call(context=owned, selected=keys,
            original_deadline_ns=selected["original_deadline_ns"],
            check=(lambda: None) if check is None else check, work=selected["work"],
            action=local_action if action is None else action, original_body=original)

    def test_exact_owned_parent_context_maps_all_source_page_kinds(self):
        cases = ((0, "count", "", 0), (3, "range", "", 0), (2, "rank", "", 0),
            (4, "primary", "", 255), (6, "write", binding.store.INDEX_IDS[0], 5120),
            (5, "candidate", "", 24))
        for phase, kind, index, ordinal in cases:
            with self.subTest(kind=kind):
                selected = arguments(phase_ordinal=phase, page_kind=kind,
                    index_id=index, page_ordinal=ordinal)
                original = copy.deepcopy(selected["context"])
                owned, keys = binding._prepare(**selected)
                self.assertEqual(set(keys), set(binding.store.CONTEXT_FIELDS))
                self.assertEqual(keys, dict(parent_plan_digest=selected["parent_plan_digest"],
                    maintenance_manifest_digest=selected["maintenance_manifest_digest"],
                    source_revision=original["sourceRevision"], operation=original["operation"],
                    operation_id=original["operationId"], request_digest=original["requestDigest"],
                    configuration_digest=original["configurationDigest"], phase_ordinal=phase,
                    page_kind=kind, index_id=index, page_ordinal=ordinal))
                selected["context"]["indexHeads"].clear()
                selected["context"]["requestDigest"] = "sha256:" + "f" * 64
                self.assertEqual(owned, original)
                self.assertEqual(keys["request_digest"], original["requestDigest"])

    def test_wrong_parent_deadline_context_and_store_coordinates_refuse(self):
        for changes in (dict(parent_plan_digest="other"), dict(maintenance_manifest_digest=True),
                dict(original_deadline_ns=True), dict(original_deadline_ns=1001),
                dict(phase_ordinal=True), dict(phase_ordinal=8), dict(page_kind="other"),
                dict(page_ordinal=True), dict(page_kind="candidate", page_ordinal=25),
                dict(phase_ordinal=7, page_kind="primary"), dict(phase_ordinal=0, page_kind="rank"),
                dict(index_id="caller-table")):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                binding._prepare(**arguments(**changes))
        for key, value in (("sourceRevision", "old"), ("operation", "webauthn.challenge.claim"),
                ("originalDeadlineNs", True), ("accepted", True), ("indexHeads", [])):
            selected = arguments()
            selected["context"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                binding._prepare(**selected)

    def test_descriptor_is_recomputed_from_exact_bytes_without_aliases(self):
        raw = b'{"original":"synthetic raw evidence"}'
        original = descriptor(raw)
        actual = binding._descriptor(raw, original, work())
        self.assertEqual(actual, original)
        self.assertIsNot(actual, original)
        for body, record in ((bytearray(raw), original), (b"", descriptor(b"")),
                (raw, {**original, "byteCount": True}), (raw, {**original, "byteCount": len(raw) + 1}),
                (raw, {**original, "digest": "sha256:" + "f" * 64}),
                (raw, {**original, "accepted": True}), (raw + b" ", original)):
            with self.subTest(body_type=type(body).__name__), self.assertRaises(ValueError):
                binding._descriptor(body, record, work())

    def test_callback_none_native_identity_original_clock_and_work_are_held(self):
        self.assertEqual(self.call(original=b"{}"), b"{}")
        for mutation in (lambda meter: setattr(meter, "input_bytes", 0),
                lambda meter: setattr(meter, "limits", QueryReadValidationLimits())):
            selected = arguments()
            with self.assertRaises(ValueError):
                self.call(values=selected, check=lambda: mutation(selected["work"]))
        with self.assertRaises(ValueError):
            self.call(check=lambda: True)
        for expired in (1000, 1001):
            self.clock.return_value = expired
            with self.assertRaises(ValueError):
                self.call()
        self.clock.return_value = 10
        with mock.patch.object(binding.os, "getpid", side_effect=(100, 101)):
            with self.assertRaises(ValueError):
                self.call()
        def cancel():
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.call(check=cancel)

    def test_literal_readback_context_and_non_reentrant_check_are_required(self):
        for raw in (b"[]", memoryview(b"{}"), {"accepted": True}):
            with self.subTest(raw_type=type(raw).__name__), self.assertRaises(ValueError):
                self.call(action=lambda guard: raw, original=b"{}")
        selected = arguments()
        owned, keys = binding._prepare(**selected)
        def alter(guard):
            keys["configuration_digest"] = "sha256:" + "f" * 64
            return b"{}"
        with self.assertRaises(ValueError):
            binding._call(context=owned, selected=keys, original_deadline_ns=1000,
                check=lambda: None, work=selected["work"], action=alter)
        held = {}
        def reenter():
            with self.assertRaises(ValueError):
                held["guard"]()
        def action(guard):
            held["guard"] = guard
            guard()
            return b"{}"
        with self.assertRaises(ValueError):
            self.call(action=action, check=reenter)

    def test_public_apis_reach_real_store_admission_without_alternate_sql_or_verdict(self):
        # Actual facade rejection, not a substituted successful store.
        for retain in (False, True):
            selected = arguments()
            selected.update(connection=object(), check=lambda: None)
            with self.subTest(retain=retain), self.assertRaises(RuntimeError):
                if retain:
                    binding.retain_original(**selected, body_bytes=b"{}", descriptor=descriptor(b"{}"))
                else:
                    binding.read_original(**selected)
        tree = ast.parse(inspect.getsource(binding))
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertIn("store.persist_page", calls)
        self.assertIn("store.read_original", calls)
        self.assertNotIn("store.read_page", calls)
        self.assertFalse(any(name.rsplit(".", 1)[-1] in
            {"connect", "commit", "rollback", "execute", "transaction", "_ValidationWork"} for name in calls))
        store_tree = ast.parse(inspect.getsource(binding.store))
        self.assertIn("lifecycle._admit", [ast.unparse(node.func)
            for node in ast.walk(store_tree) if isinstance(node, ast.Call)])


if __name__ == "__main__":
    unittest.main()
