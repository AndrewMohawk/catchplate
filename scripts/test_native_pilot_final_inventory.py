#!/usr/bin/env python3
"""Final graph and public serialization controls, not live acceptance.

The bundle fixture combines independently signed synthetic components only for
the public shape layer. It is not a coherent production scope/installation and
is not used to claim the complete retained-owner path passed.
"""
from __future__ import annotations

import ast
import copy
from functools import lru_cache
import json
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))
from serverware import native_pilot_phase_execution as execution
from serverware import native_pilot_phase_two_publication as publication
from serverware import native_pilot_supervisor as supervisor
from serverware import native_pilot_supervisor_continuation as continuation
from serverware import native_pilot_supervisor_policy as policy
from test_native_pilot_bridge_commissioning import fixture as bridge_fixture
from test_native_pilot_generation_scope import key_fixture
from test_native_pilot_ordinary_generations import context, build, result
from test_native_pilot_ordinary_keys import ROLES, canonical, encoded, labelled, sha


@lru_cache(maxsize=1)
def bundle_fixture():
    ordinary = context()
    originals = {role: result(role, json.loads(json.loads(build(ordinary, role))["payloadOriginal"]))["original"]
        for role in ROLES}
    bridge = bridge_fixture()
    operational = copy.deepcopy(bridge["runtime"])
    operational["generationAdmission"]["grants"] = {role: sha(raw.encode("ascii")) for role, raw in originals.items()}
    runtime_raw = canonical(operational)
    delivered = json.loads(bridge["common"]["delivery_raw"])
    delivered["payload"]["runtimeConfig"]["sha256"] = sha(runtime_raw)
    delivered["signatureBase64url"] = encoded(key_fixture("bridge-c9")[0].sign(
        b"serverware.policyCustodyGuestDelivery.signature/v1\0" + canonical(delivered["payload"])))
    return canonical({"runtimeOriginal": runtime_raw.decode("ascii"),
        "deliveryOriginal": canonical(delivered).decode("ascii"), "generationOriginals": originals})


class FinalGraphControls(unittest.TestCase):
    def test_all_fixed_decisions_connected_but_v18_is_separate_authority(self):
        expected = (("release", "cohort-release"), ("release", "driver-scope"), ("release", "phase-two-public"),
            ("constructed-admission", "driver-constructed"), ("generation-origin", "observe-generation-origin"),
            ("shutdown", "stop"))
        self.assertEqual(continuation.JOB_SLOTS, expected)
        self.assertEqual(supervisor.SUPPORTED_JOBS[-6:], expected)
        self.assertEqual(supervisor.SUPPORTED_JOBS, supervisor._ORDER)
        self.assertEqual(supervisor.missing_jobs(), ())
        self.assertEqual((len(supervisor._ORDER), len(execution.KEY_PURPOSES)), (164, 113))
        self.assertEqual(policy.CONTINUATION_FIELDS, policy.BRIDGE_COMMISSIONING_FIELDS + ("continuationOriginal",))
        self.assertNotEqual(policy.CONTINUATION_PURPOSE, policy.BRIDGE_COMMISSIONING_PURPOSE)
        self.assertEqual(len(policy.LAUNCH_KEY_PURPOSES), 108)

    def test_source_start_gate_precedes_child_creation_not_runtime_proof(self):
        tree = ast.parse((SCRIPTS.parent / "serverware/native_pilot_supervisor.py").read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "CommissioningSupervisor")
        start = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "start")
        calls = [ast.unparse(node.value.func) for node in start.body
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)]
        self.assertLess(calls.index("require_complete_coverage"), calls.index("self._process.start"))
        self.assertLess(calls.index("self._policy.require_final_scope"), calls.index("self._process.start"))

    def test_public_bundle_exact_literal_fixed_pin_and_result(self):
        bundle = bundle_fixture()
        raw = publication.build(bundle)
        self.assertEqual(publication.prepare_input(raw), bundle)
        expected = {"pin": {"path": "/etc/serverware/native-pilot-inputs/driver-phase-two-public.json", "sha256": sha(bundle)}}
        self.assertEqual(publication.checked_result(raw, expected), expected)
        self.assertEqual(execution.JOBS["release"][2].maximum, publication.MAX_INPUT)
        self.assertIsNone(execution.JOBS["release"][2].key)

    def test_public_originals_cannot_change_under_old_runtime_pins(self):
        for mutation in ("runtime", "grant", "missing", "extra"):
            value = json.loads(bundle_fixture())
            if mutation == "runtime":
                delivered = json.loads(value["deliveryOriginal"])
                delivered["payload"]["runtimeConfig"]["sha256"] = labelled("wrong-runtime")
                value["deliveryOriginal"] = canonical(delivered).decode("ascii")
            elif mutation == "grant":
                signed = json.loads(value["generationOriginals"][ROLES[0]])
                signed["signatureBase64url"] = encoded(bytes(64))
                value["generationOriginals"][ROLES[0]] = canonical(signed).decode("ascii")
            elif mutation == "missing": value["generationOriginals"].pop(ROLES[0])
            else: value["approved"] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): publication.build(canonical(value))

    def test_public_input_and_reported_result_are_closed(self):
        raw = publication.build(bundle_fixture())
        value = json.loads(raw)
        for changed in (dict(value, path="/tmp/not-approved.json"), dict(value, apiVersion="unknown")):
            with self.assertRaises(ValueError): publication.prepare_input(canonical(changed))
        for changed in ({"pin": {"path": "/tmp/not-approved.json", "sha256": sha(bundle_fixture())}},
                {"pin": {"path": publication.publication.DESTINATIONS[publication.PURPOSE], "sha256": labelled("different")}},
                {"pin": {"path": publication.publication.DESTINATIONS[publication.PURPOSE], "sha256": sha(bundle_fixture())}, "installed": True}):
            with self.assertRaises(ValueError): publication.checked_result(raw, changed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
