#!/usr/bin/env python3
"""Selected installation-input joins, not registry or worker execution.

The fixture contains signed synthetic histories and explicitly synthetic
independent delegation. Tiny inventory trees exercise the real inventory codec.
Result rows below test public association only, never successful owner custody.
No real validator is replaced or mocked.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from scripts import test_native_pilot_initial_state_profile as source_fixture
from scripts import test_native_pilot_adopted_ordinary_inputs as ordinary_fixture
from serverware import native_pilot_adopted_ordinary_inputs as compiler
from serverware import native_pilot_adopted_ordinary_install as installation
from serverware import native_pilot_adopted_phase_profile as phase

p = installation.p
ERRORS = (ValueError, KeyError, TypeError, InvalidSignature)
JOB = "install-ordinary-runtime"


def selection(source):
    value = copy.deepcopy(source["source"]["selections"][JOB])
    value["runtimePolicy"] = dict(apiVersion=compiler.INITIAL_STATE_RUNTIME_API,
        runtimePolicy=value["runtimePolicy"], initialStateDelegationOriginal=source["delegation_raw"].decode("ascii"),
        supervisorInventoryOriginal=source["inventory_raw"].decode("ascii"))
    return value


def checked(source, raw, result):
    name = phase.BY_NAME[JOB][0]
    phases = tuple(phase.JOBS)
    observations = {item: source["source"]["observations"][item] for item in phases[:phases.index(name) + 1]}
    return phase.checked_result(JOB, raw, result, phase=name,
        prior=ordinary_fixture.prefix(JOB, source["source"]["records"]), observations=observations, **source["clocks"])


class InitialStateInstallationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(prefix="initial-state-installation-")
        cls.addClassCleanup(directory.cleanup)
        cls.addClassCleanup(source_fixture.runtime_fixture.thaw, Path(directory.name))
        cls.source = source_fixture.fixture(Path(directory.name))
        cls.raw = ordinary_fixture.compose(cls.source["source"], JOB, selection=selection(cls.source))
        cls.prepared = installation.prepare_input(cls.raw, **cls.source["clocks"])

    def test_explicit_wrapper_keeps_catalogue_and_all_fifteen_file_originals(self):
        self.assertEqual(compiler.selection_fields(phase.BY_NAME[JOB][1]), ("runtimePolicy", "peerExpectations"))
        value = installation.installation_value(p.document(self.raw, installation.MAX_INPUT))
        self.assertEqual(value["apiVersion"], installation.INITIAL_STATE_API)
        self.assertEqual(set(value), set(installation.INITIAL_STATE_FIELDS))
        self.assertEqual(installation.base_original(value), self.source["installation_original"])
        baseline = installation.prepare_input(self.source["installation_original"], **self.source["clocks"])
        self.assertEqual(self.prepared["planned"], baseline["planned"])
        self.assertEqual(len(self.prepared["planned"]), 15)
        self.assertLessEqual(self.prepared["deadline"], baseline["deadline"])
        self.assertEqual(value["initialStateDelegationOriginal"].encode("ascii"), self.source["delegation_raw"])
        self.assertEqual(value["supervisorInventoryOriginal"].encode("ascii"), self.source["inventory_raw"])

    def test_input_one_stays_unselected_with_unchanged_result(self):
        source = self.source
        raw = ordinary_fixture.compose(source["source"], JOB)
        self.assertEqual(raw, source["installation_original"])
        baseline = installation.prepare_input(raw, **source["clocks"])
        self.assertNotIn("initialState", baseline)
        self.assertIsNone(baseline["epochLimit"])
        result = copy.deepcopy(source["source"]["records"][JOB]["result"])
        self.assertEqual(checked(source, raw, result), result)
        result["initialState"] = {}
        with self.assertRaises(ERRORS): checked(source, raw, result)

    def test_selected_wrapper_and_successor_fields_are_closed(self):
        for change in ("unknown-version", "missing-delegation", "extra", "nested-wrapper"):
            chosen = selection(self.source); wrapper = chosen["runtimePolicy"]
            if change == "unknown-version": wrapper["apiVersion"] += "-other"
            elif change == "missing-delegation": del wrapper["initialStateDelegationOriginal"]
            elif change == "extra": wrapper["current"] = True
            else: wrapper["runtimePolicy"] = copy.deepcopy(wrapper)
            with self.subTest(change=change), self.assertRaises(ERRORS):
                ordinary_fixture.compose(self.source["source"], JOB, selection=chosen)
        for change in ("missing", "extra", "legacy"):
            value = p.document(self.raw, installation.MAX_INPUT)
            if change == "missing": del value["supervisorInventoryOriginal"]
            elif change == "extra": value["workerProcess"] = {}
            else: value["apiVersion"] = installation.API
            with self.subTest(change=change), self.assertRaises(ERRORS): installation.installation_value(value)

    def test_actual_prior_history_and_resource_literal_joins_still_apply(self):
        for change in ("history", "resources"):
            source = self.source["source"]
            records, observations = copy.deepcopy(source["records"]), copy.deepcopy(source["observations"])
            if change == "history":
                name = "ordinary-initial-assemble-" + compiler.g.ROLES[0]
                records[name]["result"]["original"] += " "
            else:
                row = p.document(observations["endpoint-inputs"]["ordinaryInitialResourcesOriginal"].encode("ascii"), 65536)
                row["services"][compiler.g.ROLES[0]]["directories"]["publication-journal"]["entryCount"] = 1
                observations["endpoint-inputs"]["ordinaryInitialResourcesOriginal"] = p.canonical(row).decode("ascii")
            with self.subTest(change=change), self.assertRaises(ERRORS):
                ordinary_fixture.compose(source, JOB, selection=selection(self.source), records=records, observations=observations)

    def test_independent_delegation_and_inventory_cannot_be_substituted(self):
        for change in ("inventory", "scope", "status"):
            value = p.document(self.raw, installation.MAX_INPUT)
            if change == "inventory": value["supervisorInventoryOriginal"] += " "
            else:
                delegated = p.document(value["initialStateDelegationOriginal"].encode("ascii"), source_fixture.profile.MAX_DELEGATION)
                if change == "scope": delegated["launchSha256"] = p.sha(b"different launch")
                else: next(iter(delegated["targets"].values()))["status"] = "revoked"
                value["initialStateDelegationOriginal"] = p.canonical(delegated).decode("ascii")
            with self.subTest(change=change), self.assertRaises(ERRORS):
                installation.prepare_input(p.canonical(value), **self.source["clocks"])

    def test_selected_original_dual_caps_cannot_be_renewed(self):
        for clocks in ({"now_boottime_ns": self.prepared["deadline"]},
                {"now_unix_ns": self.prepared["epochLimit"]},
                {"boot": (self.source["clocks"]["boot"][0], 1, 999)}):
            with self.subTest(clocks=clocks), self.assertRaises(ERRORS):
                installation.prepare_input(self.raw, **(self.source["clocks"] | clocks))
        later = installation.prepare_input(self.raw,
            **(self.source["clocks"] | {"now_boottime_ns": self.source["clocks"]["now_boottime_ns"] + 1}))
        self.assertEqual((later["deadline"], later["epochLimit"]),
            (self.prepared["deadline"], self.prepared["epochLimit"]))

    def test_selected_result_requires_exact_registry_pins_and_worker_shape_only(self):
        result = copy.deepcopy(self.source["source"]["records"][JOB]["result"])
        context = self.prepared["initialState"]
        result.update(apiVersion=installation.INITIAL_STATE_RESULT_API, inputSha256=p.sha(self.raw),
            initialState=dict(stateSha256=p.sha(context["stateOriginal"]), stateGeneration=1,
                workerPolicySha256=p.sha(context["workerPolicyOriginal"]), supervisorInventorySha256=p.sha(self.source["inventory_raw"])),
            workerProcess=dict(pid=501, uid=0, gid=0, startTimeTicks=123, parentPid=500))
        self.assertEqual(checked(self.source, self.raw, result), result)
        for change in ("legacy-result", "state", "generation", "policy", "inventory", "worker", "extra"):
            value = copy.deepcopy(result)
            if change == "legacy-result": value["apiVersion"] = installation.RESULT_API
            elif change == "generation": value["initialState"]["stateGeneration"] = 2
            elif change == "worker": value["workerProcess"]["pid"] = True
            elif change == "extra": value["workerProcess"]["startedSuccessfully"] = True
            else:
                field = {"state": "stateSha256", "policy": "workerPolicySha256", "inventory": "supervisorInventorySha256"}[change]
                value["initialState"][field] = p.sha(b"other source")
            with self.subTest(change=change), self.assertRaises(ERRORS): checked(self.source, self.raw, value)


class InitialStateExecutionSourceControls(unittest.TestCase):
    """Source-order guards only; these do not construct or claim real owners."""

    @staticmethod
    def method(path, name):
        tree = ast.parse((ROOT / path).read_text())
        return next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)

    @staticmethod
    def calls(node, function):
        return sorted((item for item in ast.walk(node) if isinstance(item, ast.Call)
            and ast.unparse(item.func) == function), key=lambda item: item.lineno)

    def test_selected_actual_install_registry_worker_order_and_nonrecursive_guard(self):
        path = "serverware/native_pilot_adopted_phase_execution.py"
        perform = self.method(path, "_perform")
        install = self.calls(perform, "ordinary_install.install")[0]
        selected = self.calls(perform, "self._install_initial_state")[0]
        self.assertLess(install.lineno, selected.lineno)
        branch = next(node for node in ast.walk(perform) if isinstance(node, ast.If)
            and "ordinary_install.INITIAL_STATE_API" in ast.unparse(node.test))
        self.assertIn(selected, list(ast.walk(branch)))
        hook = self.method(path, "_install_initial_state")
        registry = self.calls(hook, "InitialStateInstallation.install")[0]
        worker = self.calls(hook, "CurrentHeadWorkerProcess.prepare")[0]
        start = self.calls(hook, "self._head_worker.start")[0]
        self.assertLess(registry.lineno, worker.lineno)
        self.assertLess(worker.lineno, start.lineno)
        self.assertEqual(ast.unparse(next(item.value for item in worker.keywords if item.arg == "check")),
            "self._initial_registry.check_retained")
        for handler in (node for node in ast.walk(hook) if isinstance(node, ast.ExceptHandler)):
            self.assertIn("error.owner", ast.unparse(handler.body[0]))
            self.assertIsInstance(handler.body[-1], ast.Raise)
        during = self.method(path, "_during")
        for ready, check in (("self._registry_ready", "self._initial_registry.check_retained"),
                ("self._head_worker_ready", "self._head_worker.check")):
            guarded = next(node for node in ast.walk(during) if isinstance(node, ast.If)
                and ast.unparse(node.test) == ready)
            self.assertEqual(len(self.calls(guarded, check)), 1)

    def test_completion_rejection_still_closes_known_owners_in_safe_order(self):
        path = "serverware/native_pilot_adopted_phase_execution.py"
        final = self.method(path, "final_result")
        outer = final.body[1]  # Literal docstring, then the failure-latching try.
        self.assertIsInstance(outer, ast.Try)
        self.assertIn("self._failed = True", ast.unparse(outer.handlers[0]))
        proof = self.calls(final, "self._head_worker.require_complete")[0]
        self.assertLess(proof.lineno, next(node.lineno for node in ast.walk(final) if isinstance(node, ast.Return)))
        close = self.method(path, "close")
        worker = self.calls(close, "self._head_worker.close")[0]
        registry = self.calls(close, "self._initial_registry.close")[0]
        ordinary = self.calls(close, "self._ordinary_install.close")[0]
        self.assertLess(worker.lineno, registry.lineno)
        self.assertLess(registry.lineno, ordinary.lineno)
        self.assertIn("self._failed", ast.unparse(next(item.value for item in worker.keywords if item.arg == "cancel")))
        main = self.method("scripts/run_native_pilot_authority_coordinator.py", "main")
        self.assertLess(self.calls(main, "executor.cancel_current_head_worker")[0].lineno,
            self.calls(main, "owner.close")[0].lineno)
        completion = self.calls(main, "executor.final_result")[0]
        protected = next(node for node in ast.walk(main) if isinstance(node, ast.Try)
            and any(completion in list(ast.walk(item)) for item in node.body)
            and any("failed = True" in ast.unparse(handler) and not any(isinstance(item, ast.Raise)
                for item in ast.walk(handler)) for handler in node.handlers)
            and node.lineno > self.calls(main, "owner.close")[0].lineno)
        self.assertLess(protected.end_lineno, self.calls(main, "executor.close")[0].lineno)
        self.assertLess(self.calls(main, "executor.close")[0].lineno, self.calls(main, "channel.close")[0].lineno)


if __name__ == "__main__":
    unittest.main()
