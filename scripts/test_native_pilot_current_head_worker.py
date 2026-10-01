#!/usr/bin/env python3
"""Bounded source controls for the actual worker's irreversible IO ordering.

These do not manufacture a worker, installed runtime or authoritative state.
The companion profile suite checks typed decisions; the state-owner suite
checks real locks and publication. This suite guards their runtime connection.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CurrentHeadWorkerConnectionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse((ROOT / "serverware/native_pilot_current_head_worker.py").read_text())
        cls.owner = next(node for node in cls.tree.body
            if isinstance(node, ast.ClassDef) and node.name == "CurrentHeadWorker")
        cls.methods = {node.name: node for node in cls.owner.body if isinstance(node, ast.FunctionDef)}

    def source(self, method):
        return ast.unparse(self.methods[method])

    def test_exact_live_state_lock_spans_decision_consume_and_pair_before_release(self):
        calls = [(ast.unparse(node.func), node.lineno) for node in ast.walk(self.methods["run"])
            if isinstance(node, ast.Call)]
        def position(name):
            matches = [line for actual, line in calls if actual == name]
            self.assertEqual(len(matches), 1, name)
            return matches[0]
        names = ("profile.bounds", "self._state.acquire_shared", "profile.compose",
            "self._state.consume", "self._state.publish_pair", "self._state.release")
        self.assertEqual([position(name) for name in names], sorted(position(name) for name in names))
        run = self.source("run")
        self.assertIn("state, self._prepared", run)
        self.assertIn("prepared['receiptOriginal']", run)
        self.assertIn("prepared['inputOriginal'], prepared['approvalOriginal']", run)
        self.assertIn("self._prepared['value']['decisionDirectory']", run)
        self.assertNotIn("finally:\n            self._state.release", run)

    def test_fixed_eight_order_retains_first_conductor_and_original_dual_caps(self):
        run = self.source("run")
        self.assertIn("enumerate(delivery.intake.JOB_NAMES)", run)
        self.assertIn("self.decisions == index", run)
        self.assertIn("first_conductor_raw=self._first_conductor", run)
        self.assertIn("self._first_conductor = bytes(prepared['conductorOriginal'])", run)
        self.assertLess(run.index("self._state.release()"), run.index("self.decisions += 1"))
        self.assertIn("delivery.intake.profile.API", run)
        self.assertNotIn("profile.REQUEST_API", run)
        self.assertIn("min(self._active[name], bounds[name])", run)
        self.assertIn("min(self._active[name], prepared[name])", run)
        self.assertIn("if self.decisions < len(delivery.intake.JOB_NAMES):", run)
        check = self.source("check")
        self.assertIn("self._last <= now < deadline", check)
        self.assertIn("self._wall <= wall < expiry", check)
        self.assertNotIn("self._state.check", check)

    def test_real_protected_sources_and_partial_state_owner_retained_before_use(self):
        opened = self.source("open")
        self.assertIn("_Protected(owner._sources, supervisor_inventory_fd", opened)
        self.assertIn("_Protected(owner._sources, policy_fd", opened)
        self.assertLess(opened.index("owner._runtime = _SelfRuntime()"), opened.index("owner._runtime.admit("))
        self.assertLess(opened.index("owner._runtime.admit("), opened.index("profile.prepare("))
        self.assertIn("StateStore.open(directory=owner._prepared['value']['stateDirectory'], check=owner.check)", opened)
        self.assertIn("type(error.owner) is StateStore", opened)
        self.assertIn("owner._state = error.owner", opened)
        self.assertIn("raise CurrentHeadWorkerError(owner) from error", opened)
        self.assertIn("owner._require_absent(delivery.filenames(job))", opened)
        read = self.source("_read")
        self.assertLess(read.index("row = self._handle(fd)"), read.index("public_io._input(fd, maximum)"))
        self.assertIn("self._bytes + identity[6] <= MAX_RETAINED_BYTES", read)

    def test_waiting_for_evidence_is_bounded_by_already_received_request(self):
        run = self.source("run")
        request = run.index("request = self._read(")
        narrowed = run.index("self._active = dict(")
        evidence = run.index("self._wait_name(names['evidence'])")
        self.assertLess(request, narrowed)
        self.assertLess(narrowed, evidence)
        wait = self.source("_wait_name")
        self.assertIn("caps['deadline'] - self._last", wait)
        self.assertIn("caps['epochLimit'] - self._wall", wait)
        self.assertIn("select.select([], [], [], delay)", wait)
        self.assertGreaterEqual(wait.count("self.check()"), 2)

    def test_cleanup_is_sticky_descriptor_only_and_does_not_require_live_clock(self):
        close = self.source("close")
        self.assertIn("if self._closed:", close)
        self.assertIn("not self._closing", close)
        self.assertLess(close.index("self._closing = True"), close.index("self._state.close()"))
        self.assertLess(close.index("self._state.close()"), close.index("os.close(fd)"))
        self.assertLess(close.index("fd, row[0] ="), close.index("os.close(fd)"))
        self.assertNotIn("self.check(", close)
        self.assertNotIn("self._clocks(", close)
        self.assertIn("raise CurrentHeadWorkerError(self) from error", close)
        self.assertNotIn("self._closing = False", close)

    def test_worker_has_no_signer_updater_fallback_or_rollback_actions(self):
        forbidden = {"sign", "signing_key", "from_private_bytes", "unlink", "remove", "rmdir",
            "mkdir", "rename", "replace", "system", "execve", "fork", "popen", "acquire_exclusive"}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, forbidden)
        run = self.source("run")
        self.assertIn("self._used = self._running = True", run)
        self.assertIn("not self._used", run)
        self.assertIn("not self._running", run)
        self.assertIn("self._failed = True", run)
        self.assertIn("self._runtime.check(installed=True)", run)


if __name__ == "__main__":
    unittest.main()
