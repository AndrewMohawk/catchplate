"""UNRUN genuine input/source controls; no measured or native success double.

The actual request commitments and source root/head classes are exercised.
The measured factory is inspected, not replaced with a successful producer.
An explicit raised boundary proves malformed inputs cannot reach it. These
controls do not establish protected-descriptor, native SQL or durable custody
acceptance; the actual producer and measured process remain required.
"""
from __future__ import annotations

import ast
import copy
import inspect
import unittest
from unittest import mock

from serverware import authority_jit_compound_service as service
from test_authority_jit_connected_originals import connected_fixture
from test_authority_jit_original_configuration import work
from test_authority_jit_original_authorization import WINDOW, DEADLINE, MONOTONIC, clocks


class MeasuredBoundary(BaseException):
    pass


def arguments():
    fixture = connected_fixture()
    return dict(request=fixture["request"],
        business_before_roots=tuple(root.json_projection() for root in fixture["business_before_roots"]),
        authorization_before_roots=tuple(root.json_projection() for root in fixture["authorization_before_roots"]),
        expected_counted_heads=tuple(dict(indexId=head.index_id, indexRevision=head.index_revision,
            rootDigest=head.index_root.digest, leafCount=head.index_root.count)
            for head in fixture["counted_before_heads"]),
        live_window=WINDOW, original_deadline_ns=DEADLINE, check=lambda stage: None, work=work())


class JitCompoundServiceControls(unittest.TestCase):
    def test_actual_typed_request_and_complete_four_plus_four_twelve_inputs_are_detached(self):
        values = arguments()
        selected = service._inputs_on_work(values["request"], values["business_before_roots"],
            values["authorization_before_roots"], values["expected_counted_heads"], values["work"])
        expected = copy.deepcopy(selected)
        values["request"]["arguments"].clear()
        values["business_before_roots"][0]["rootDigest"] = "sha256:" + "f" * 64
        values["authorization_before_roots"][0]["leafCount"] += 1
        values["expected_counted_heads"][0]["rootDigest"] = "sha256:" + "e" * 64
        self.assertEqual(selected, expected)
        self.assertEqual(tuple(map(len, selected[1:])), (4, 4, 12))
        self.assertGreater(values["work"].input_bytes, 0)
        self.assertGreater(values["work"].hash_work, 0)

    def test_exact_root_classes_original_request_and_head_inventory_refuse_before_factory(self):
        for kind in ("operation", "request", "class", "missing-root", "root-bool", "head-order", "head-bool"):
            values = arguments()
            if kind == "operation": values["request"]["operation"] = "jit.decide"
            if kind == "request": values["request"]["requestDigest"] = "sha256:" + "0" * 64
            if kind == "class":
                values["business_before_roots"], values["authorization_before_roots"] = (
                    values["authorization_before_roots"], values["business_before_roots"])
            if kind == "missing-root": values["authorization_before_roots"] = values["authorization_before_roots"][:-1]
            if kind == "root-bool": values["authorization_before_roots"][0]["rootRevision"] = True
            if kind == "head-order": values["expected_counted_heads"] = values["expected_counted_heads"][::-1]
            if kind == "head-bool": values["expected_counted_heads"][0]["leafCount"] = True
            with self.subTest(kind=kind), mock.patch.object(service, "_producer_on_work",
                    side_effect=AssertionError("invalid originals reached measured factory")), self.assertRaises(ValueError):
                service._produce_on_work(object(), **values)

    def test_valid_inputs_reach_only_real_factory_boundary_and_original_small_work_refuses_first(self):
        values = arguments()
        with mock.patch.object(service, "_producer_on_work", side_effect=MeasuredBoundary()) as native:
            with self.assertRaises(MeasuredBoundary):
                service._produce_on_work(object(), **values)
        self.assertEqual(native.call_count, 1)
        self.assertIs(native.call_args.kwargs["work"], values["work"])
        self.assertIs(native.call_args.kwargs["live_window"], WINDOW)
        values["work"] = work(max_input_bytes=128)
        with mock.patch.object(service, "_producer_on_work", side_effect=AssertionError("small work reached factory")):
            with self.assertRaises(ValueError):
                service._produce_on_work(object(), **values)

    def test_actual_measured_factory_has_only_planner_read_descriptor_and_held_page_signer(self):
        tree = ast.parse(inspect.getsource(service))
        methods = {item.name: item for item in tree.body if isinstance(item, ast.FunctionDef)}
        source = ast.unparse(methods["_producer_on_work"])
        self.assertIn("pages._caller_on_work(process, live_window=live_window, work=work, processing_owner=processing_owner)", source)
        self.assertIn("caller._configured.local_role == 'planner'", source)
        self.assertIn("role='planner', signing=False, read_descriptor=_READ_DSN, work=work", source)
        self.assertIn("private is None", source)
        self.assertIn("mapping._producer_from_configuration_on_work", source)
        self.assertIn("read_dsn=dsn, page_caller=caller, work=work", source)
        self.assertEqual(service._READ_DSN, "SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN")
        self.assertNotIn("WRITER_POSTGRES_DSN", inspect.getsource(service))
        self.assertNotIn("os.environ", source)
        self.assertNotIn("planner_private_key=", source)

    def test_actual_call_preserves_producer_stage_and_sole_native_custody_owner(self):
        tree = ast.parse(inspect.getsource(service._produce_on_work))
        text = ast.unparse(tree)
        self.assertLess(text.index("_inputs_on_work("), text.index("_producer_on_work("))
        self.assertIn("type(producer) is production._JitCompoundProducer", text)
        self.assertIn("production._JitCompoundProducer.produce(producer", text)
        self.assertIn("type(result) is production.ProducedJitCompoundPlan", text)
        self.assertIn("type(stage) in (production._ProductionStage, compound._Stage)", text)
        self.assertIn("evidence.production._callback(active_work, lambda: check(stage)) is None", text)
        self.assertLess(text.index("production._JitCompoundProducer.produce(producer"),
            text.index("pages._original_interval_on_work("))
        self.assertIn("expires = window[0] + original_deadline_ns - window[1]", text)
        for forbidden in ("stage.check(", "retain_original=", "read_original=", "planner_private_key=",
                "_ValidationWork(", "acquire_pass(", "verify_retained("):
            self.assertNotIn(forbidden, text)

    def test_final_original_bound_is_not_extended_by_a_wider_page_window(self):
        original = MONOTONIC + 200
        expires = WINDOW[0] + original - WINDOW[1]
        with clocks({"elapsed": 199}) as state:
            self.assertEqual(service.pages._original_interval_on_work(
                WINDOW, WINDOW[0], expires, original, work()), original)
            state["elapsed"] = 200
            with self.assertRaises(ValueError):
                service.pages._original_interval_on_work(WINDOW, WINDOW[0], expires, original, work())


if __name__ == "__main__":
    unittest.main()
