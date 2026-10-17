#!/usr/bin/env python3
"""Fixed-parent public terminal/argv controls, not a live three-role ceremony.

Result records are explicitly synthetic. Source controls verify that the real
parent's fixed spawn/reap/cleanup seams remain connected; they are not process
completion evidence. The companion child suite exercises actual kernel peers.
No installed runtime, protected approval or successful owner is fabricated.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from scripts import run_native_pilot_startup_child as child_cli
from catchplate import native_pilot_startup as startup

p = startup.p


def result(role):
    common = dict(pilotAcceptanceVerified=False, productionReleaseEligible=False)
    if role == "lifecycle":
        return dict(common, apiVersion="catchplate.nativePilotLifecycleResult/v1", status="stopped-cleanup-complete",
            stage="adopted-finish", coldJobsCompleted=66, adoptedJobsCompleted=176, coldBundleSha256=p.sha(b"synthetic bundle"))
    if role == "provider":
        return dict(common, apiVersion="catchplate.nativePilotApprovalProviderResult/v1", status="complete-public-transcript",
            stage="complete-public-transcript", approvalsDelivered=244, completionReceipts=2)
    return dict(common, apiVersion="catchplate.nativePilotCurrentHeadDecisionServiceResult/v1", status="complete-eight-decisions",
        stage="eight-independent-pairs-delivered", decisionsDelivered=8)


def checked(value, role, **kwargs):
    return startup.role_result(p.canonical(value) + b"\n", role, **(dict(exit_code=0, admitted=True) | kwargs))


class StartupTerminalControls(unittest.TestCase):
    def test_all_three_existing_success_records_are_literal_and_nonproduction(self):
        for role in startup.profile.ROLES:
            value = result(role); original = copy.deepcopy(value)
            self.assertEqual(checked(value, role), value)
            self.assertEqual(value, original)
            self.assertFalse(value["pilotAcceptanceVerified"])
            self.assertFalse(value["productionReleaseEligible"])

    def test_success_requires_exact_counts_stage_and_actual_normal_zero_exit(self):
        counts = {"lifecycle": ("coldJobsCompleted", "adoptedJobsCompleted"),
            "provider": ("approvalsDelivered", "completionReceipts"), "decisions": ("decisionsDelivered",)}
        for role in startup.profile.ROLES:
            for field in counts[role]:
                for changed in (True, result(role)[field] - 1):
                    value = result(role); value[field] = changed
                    with self.subTest(role=role, field=field, changed=changed), self.assertRaises(ValueError): checked(value, role)
            for exit_code in (1, -9, 127, True):
                with self.subTest(role=role, exit_code=exit_code), self.assertRaises(ValueError):
                    checked(result(role), role, exit_code=exit_code)
            value = result(role); value["stage"] = "opening"
            with self.subTest(role=role), self.assertRaises(ValueError): checked(value, role)

    def test_failed_known_cleanup_is_not_success_and_unknown_never_passes(self):
        for role in startup.profile.ROLES:
            value = result(role); value.update(status="failed-cleanup-complete", stage="opening")
            self.assertEqual(checked(value, role, exit_code=1), value)
            with self.assertRaises(ValueError): checked(value, role)
            value["status"] = "cleanup-unknown-owner-retained"
            with self.assertRaises(ValueError): checked(value, role, exit_code=1)
        value = dict(apiVersion="catchplate.nativePilotStartupChildResult/v1", role="provider",
            status="failed-cleanup-complete", pilotAcceptanceVerified=False, productionReleaseEligible=False)
        self.assertEqual(checked(value, "provider", exit_code=1, admitted=False), value)
        self.assertEqual(checked(value, "provider", exit_code=1, admitted=True), value)
        for options in ({"exit_code": 0, "admitted": False}, {"exit_code": 0, "admitted": True}):
            with self.subTest(options=options), self.assertRaises(ValueError): checked(value, "provider", **options)

    def test_extra_output_missing_newline_wrong_role_and_release_claims_refuse(self):
        raw = p.canonical(result("provider")) + b"\n"
        for bad in (raw[:-1], raw + b"\n", raw + raw, b" " + raw):
            with self.subTest(raw=bad[:32]), self.assertRaises(ValueError):
                startup.role_result(bad, "provider", exit_code=0, admitted=True)
        with self.assertRaises(ValueError): checked(result("provider"), "lifecycle")
        for changed in ({"pilotAcceptanceVerified": True}, {"productionReleaseEligible": True}, {"extra": True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError): checked(result("provider") | changed, "provider")

    def test_only_fixed_positional_child_commands_and_public_descriptors_exist(self):
        arguments = dict(configuration_fd=5, configuration_sha256=p.sha(b"configuration"),
            supervisor_inventory_fd=6, supervisor_inventory_sha256=p.sha(b"inventory"),
            parent_pid=1234, parent_start_time_ticks=5678)
        for role in startup.profile.ROLES:
            command = startup.child_command(role, **arguments)
            prefix = startup.artifacts.SUPERVISOR_COMMAND[:-1]
            self.assertEqual(command[:len(prefix)], prefix)
            selected = child_cli._arguments(command[len(prefix):])
            self.assertEqual(selected, dict(role=role, **arguments))
            self.assertFalse(any("key" in value for value in command))
        for role in ("arbitrary", "--command", "provider;true"):
            with self.subTest(role=role), self.assertRaises(ValueError): startup.child_command(role, **arguments)


class StartupConnectedSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(startup.__file__).read_text(encoding="ascii")
        cls.tree = ast.parse(cls.source)
        owner = next(node for node in cls.tree.body if isinstance(node, ast.ClassDef) and node.name == "Startup")
        cls.methods = {node.name: node for node in owner.body if isinstance(node, ast.FunctionDef)}

    def test_spawn_is_fixed_public_only_and_admission_precedes_any_key_transfer(self):
        spawn = self.methods["_spawn"]
        popen = [node for node in ast.walk(spawn) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "Popen"]
        self.assertEqual(len(popen), 1)
        passed = next(row.value for row in popen[0].keywords if row.arg == "pass_fds")
        self.assertEqual(ast.unparse(passed), "(self._configuration.fd, self._inventory.fd)")
        admission = self.methods["wait_admission"]
        calls = [node for node in ast.walk(admission) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        prepare = next(node for node in calls if node.func.attr == "admission")
        send = next(node for node in calls if node.func.attr == "send")
        self.assertLess(prepare.lineno, send.lineno)
        self.assertNotIn("read_public", {node.func.attr for node in calls})
        self.assertNotIn("read_private", {node.func.attr for node in calls})
        self.assertEqual(startup._ADMIT_ORDER, ("decisions", "provider", "lifecycle"))

    def test_cleanup_observes_after_expiry_but_never_kills_admitted_roles_into_success(self):
        close = ast.get_source_segment(self.source, self.methods["close"])
        collect = ast.get_source_segment(self.source, self.methods["_collect"])
        self.assertIn("cleanup_deadline=cleanup_deadline", close)
        self.assertIn("self._cleanup_clock(cleanup_deadline)", collect)
        self.assertEqual(startup._CLEANUP_WAIT_NS, 5_000_000_000)
        self.assertNotIn("SIGKILL", self.source)
        self.assertIn('not row["admitted"]', collect)
        self.assertIn('not row["stdout_eof"] or not row["stderr_eof"]', collect)
        self.assertIn("os.WEXITED | os.WNOWAIT | os.WNOHANG", collect)
        self.assertIn('os.waitid(os.P_PIDFD, row["pidfd"], os.WEXITED)', collect)
        self.assertIn('row["reap_attempted"] = True', collect)
        self.assertIn("role_result", collect)
        self.assertIn('row["reaped"] = True', collect)


if __name__ == "__main__": unittest.main()
