#!/usr/bin/env python3
"""Fixed command/result and source ownership controls, not installed execution.

No runtime admission or successful process owner is fabricated. Actual kernel
storage controls live in the adjacent commit suite; this suite does not claim
that a worker was launched or that eight real decisions were produced.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import native_pilot_runtime_artifacts as artifacts
from scripts import native_pilot_supervisor_runtime_entrypoint as entrypoint
from scripts import run_native_pilot_current_head_worker as cli
from serverware import native_pilot_current_head_worker_process as worker

p = worker.p


def completed():
    return dict(apiVersion="serverware.nativePilotCurrentHeadWorkerResult/v1", mode=cli.MODE,
        status="complete-eight-decisions", stage="eight-authoritative-state-decisions-published",
        decisionsPublished=8, stateUpdateOutcome="not-selected",
        pilotAcceptanceVerified=False, productionReleaseEligible=False)


def command_fields():
    return dict(supervisor_inventory_fd=10, supervisor_inventory_sha256="sha256:" + "1" * 64,
        policy_fd=11, policy_sha256="sha256:" + "2" * 64)


class CurrentHeadWorkerProcessControls(unittest.TestCase):
    def test_fixed_command_uses_existing_closed_supervisor_entrypoint(self):
        values = command_fields()
        command = worker.child_command(**values)
        prefix = artifacts.SUPERVISOR_COMMAND[:-1]
        self.assertEqual(command[:len(prefix)], prefix)
        arguments = command[len(prefix):]
        self.assertEqual(cli._arguments(arguments), (cli.MODE, values))
        self.assertTrue(entrypoint.valid_arguments(arguments))
        self.assertEqual(len(arguments), 9)

    def test_no_aliased_fds_out_of_range_or_uncanonical_pins(self):
        for key, value in (("policy_fd", 10), ("policy_fd", 2), ("policy_fd", True),
                ("supervisor_inventory_fd", 1 << 31), ("policy_sha256", "2" * 64),
                ("supervisor_inventory_sha256", "sha256:" + "A" * 64)):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                worker.child_command(**(command_fields() | {key: value}))

    def test_exact_success_is_eight_decisions_and_explicitly_not_acceptance(self):
        value = completed()
        self.assertEqual(worker.terminal_result(p.canonical(value) + b"\n", exit_code=0), value)
        self.assertFalse(value["pilotAcceptanceVerified"] or value["productionReleaseEligible"])

    def test_partial_unknown_forged_or_oversized_success_refuses(self):
        for key, value in (("decisionsPublished", 7), ("decisionsPublished", True),
                ("status", "cleanup-unknown-owner-retained"), ("stage", "opening"),
                ("mode", cli.UPDATE_MODE), ("stateUpdateOutcome", "completed"),
                ("pilotAcceptanceVerified", True), ("productionReleaseEligible", True),
                ("extra", None)):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                worker.terminal_result(p.canonical(completed() | {key: value}) + b"\n", exit_code=0)
        raw = p.canonical(completed()) + b"\n"
        for value in (raw[:-1], raw + raw, b" " + raw, raw + b" " * 4096):
            with self.assertRaises(ValueError): worker.terminal_result(value, exit_code=0)
        for code in (1, -15, True):
            with self.assertRaises(ValueError): worker.terminal_result(raw, exit_code=code)

    def test_only_exact_failed_cleanup_record_can_be_known_failure(self):
        value = completed() | dict(status="failed-cleanup-complete", stage="opening", decisionsPublished=0)
        raw = p.canonical(value) + b"\n"
        self.assertEqual(worker.terminal_result(raw, exit_code=1), value)
        with self.assertRaises(ValueError): worker.terminal_result(raw, exit_code=0)
        for status in ("cleanup-unknown-owner-retained", "killed", "complete-eight-decisions"):
            changed = copy.deepcopy(value); changed["status"] = status
            with self.assertRaises(ValueError): worker.terminal_result(p.canonical(changed) + b"\n", exit_code=1)

    def test_actual_runtime_admission_and_partial_process_owner_are_source_connected(self):
        tree = ast.parse((ROOT / "serverware/native_pilot_current_head_worker_process.py").read_text())
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "CurrentHeadWorkerProcess")
        methods = {node.name: ast.unparse(node) for node in cls.body if isinstance(node, ast.FunctionDef)}
        self.assertIn("owner._runtime.admit(owner._inventory.raw, supervisor=True)", methods["prepare"])
        self.assertIn("raise CurrentHeadWorkerProcessError(owner)", methods["prepare"])
        launch = methods["start"]
        self.assertLess(launch.index("self._spawn_uncertain = True"), launch.index("subprocess.Popen"))
        self.assertIn("pass_fds=(self._inventory.fd, self._policy.fd)", launch)
        self.assertIn("env={}", launch)
        self.assertIn("os.pidfd_open(self._child.pid, 0)", launch)
        self.assertIn("self._outer()", methods["_retained"])
        source = ast.unparse(tree)
        for forbidden in ("shell=True", "os.kill(", ".terminate(", ".kill(", ".poll(", ".wait(", "SIGKILL"):
            self.assertNotIn(forbidden, source)

    def test_terminal_cleanup_requires_eof_exact_result_and_consuming_pidfd_reap(self):
        tree = ast.parse((ROOT / "serverware/native_pilot_current_head_worker_process.py").read_text())
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "CurrentHeadWorkerProcess")
        methods = {node.name: ast.unparse(node) for node in cls.body if isinstance(node, ast.FunctionDef)}
        observe = methods["_observe"]
        self.assertIn("not self._stdout_eof or not self._stderr_eof", observe)
        self.assertIn("observed.si_code == os.CLD_EXITED", observe)
        self.assertIn("terminal_result(bytes(self._stderr), exit_code=observed.si_status)", observe)
        self.assertLess(observe.index("self._reap_attempted = True"),
            observe.index("actual = os.waitid(os.P_PIDFD, self._pidfd, os.WEXITED)"))
        self.assertIn("self._child.returncode == 0", methods["require_complete"])
        self.assertIn("signal.pidfd_send_signal(self._pidfd, signal.SIGTERM", methods["cancel"])
        self.assertNotIn("self._outer()", methods["_collect"] + methods["cancel"] + methods["close"])
        self.assertLess(methods["close"].index("self._collect()"), methods["close"].index("self._runtime.close()"))


if __name__ == "__main__": unittest.main()
