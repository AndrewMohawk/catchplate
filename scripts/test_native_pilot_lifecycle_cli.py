#!/usr/bin/env python3
"""Pure invocation/source-order controls and one real result-pipe primitive.

No live commissioning owner, independent approval, private key or successful
process lifecycle is fabricated, mocked or executed by these controls.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS.parent))
from scripts import run_native_pilot_lifecycle as cli
from serverware.native_pilot_genesis_jobs import KEY_PURPOSES as COLD_KEYS
from serverware.native_pilot_adopted_phase_profile import KEY_PURPOSES as ADOPTED_KEYS


def arguments():
    numbers = {"supervisor-inventory-fd": "3", "listener-configuration-fd": "4", "approval-fd": "5",
        "approval-peer-pid": "9000", "approval-peer-uid": "0", "approval-peer-gid": "0"}
    result = [cli.MODE]
    for flag, kind in cli._PREFIX:
        result += ["--" + flag, "sha256:" + "1" * 64 if kind == "sha" else numbers[flag]]
    for family, purposes in (("cold", COLD_KEYS), ("adopted", ADOPTED_KEYS)):
        for purpose in purposes:
            result += ["--" + family + "-authority-key", purpose + "=6"]
    return result


def parsed(value=None):
    return cli._arguments(arguments() if value is None else value, COLD_KEYS, ADOPTED_KEYS)


def changed(flag, value):
    result = arguments(); result[result.index("--" + flag) + 1] = value
    return result


def source():
    return ast.parse((SCRIPTS / "run_native_pilot_lifecycle.py").read_text())


def calls(tree, receiver, method):
    return sorted(node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and node.func.attr == method
        and isinstance(node.func.value, ast.Name) and node.func.value.id == receiver)


class LifecycleCliControls(unittest.TestCase):
    def test_exact_36_and_123_purposes_allow_shared_actual_key_fd(self):
        self.assertEqual((len(COLD_KEYS), len(ADOPTED_KEYS)), (36, 123))
        selected = parsed()
        self.assertEqual(tuple(selected["cold_authority_key_fds"]), COLD_KEYS)
        self.assertEqual(tuple(selected["adopted_authority_key_fds"]), ADOPTED_KEYS)
        self.assertEqual(set(selected["cold_authority_key_fds"].values()), {6})
        self.assertEqual(set(selected["adopted_authority_key_fds"].values()), {6})
        self.assertEqual(len(arguments()), 335)

    def test_legacy_modes_and_arbitrary_flags_do_not_select_lifecycle(self):
        for mode in ("--run-native-pilot", "--run-adopted-native-pilot", "--run-native-genesis-rendezvous",
                "--run-module", "--help"):
            with self.subTest(mode=mode), self.assertRaises(ValueError): parsed([mode] + arguments()[1:])
        unknown = arguments(); unknown[1] = "--command"
        with self.assertRaises(ValueError): parsed(unknown)

    def test_exact_prefix_count_and_order_are_required(self):
        reordered = arguments(); reordered[1:5] = reordered[3:5] + reordered[1:3]
        for value in (arguments() + ["--help"], arguments()[:-2], arguments()[1:], reordered,
                tuple(arguments()), []):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError): parsed(value)

    def test_numbers_are_canonical_and_bounded(self):
        for flag, value in (("listener-configuration-fd", "03"), ("listener-configuration-fd", "+4"),
                ("listener-configuration-fd", "2"), ("listener-configuration-fd", str(1 << 31)),
                ("approval-peer-pid", "1"), ("approval-peer-uid", "-1"),
                ("approval-peer-gid", str((1 << 32) - 1)), ("approval-peer-uid", True)):
            with self.subTest(flag=flag, value=value), self.assertRaises(ValueError): parsed(changed(flag, value))
        self.assertEqual(parsed(changed("approval-peer-uid", str((1 << 32) - 2)))["approval_peer_uid"],
            (1 << 32) - 2)

    def test_independent_public_hashes_are_exact_lowercase(self):
        for flag in ("supervisor-inventory-sha256", "listener-configuration-sha256"):
            for value in ("1" * 64, "sha256:" + "A" * 64, "sha256:" + "1" * 63, "sha256:" + "1" * 65):
                with self.subTest(flag=flag, value=value), self.assertRaises(ValueError): parsed(changed(flag, value))

    def test_public_channel_and_keys_do_not_numerically_alias(self):
        for flag, value in (("listener-configuration-fd", "3"), ("approval-fd", "4")):
            with self.assertRaises(ValueError): parsed(changed(flag, value))
        for key_flag in ("--cold-authority-key", "--adopted-authority-key"):
            for fd in (3, 4, 5):
                value = arguments(); position = value.index(key_flag) + 1
                value[position] = value[position].split("=", 1)[0] + "=" + str(fd)
                with self.subTest(key_flag=key_flag, fd=fd), self.assertRaises(ValueError): parsed(value)

    def test_key_families_purposes_and_source_order_are_closed(self):
        for family, purposes in (("cold", COLD_KEYS), ("adopted", ADOPTED_KEYS)):
            position = arguments().index("--" + family + "-authority-key")
            for literal in ("unknown=6", purposes[1] + "=6", purposes[0] + "=06", purposes[0] + "=6=7"):
                value = arguments(); value[position + 1] = literal
                with self.subTest(family=family, literal=literal), self.assertRaises(ValueError): parsed(value)
            value = arguments(); value[position] = "--authority-key"
            with self.assertRaises(ValueError): parsed(value)
        with self.assertRaises(ValueError): cli._arguments(arguments(), COLD_KEYS[:-1], ADOPTED_KEYS)

    def test_runtime_admission_precedes_real_owners_and_full_staged_order(self):
        tree = source()
        ordered = [calls(tree, receiver, method)[0] for receiver, method in (
            ("runtime", "admit"), ("CommissioningLifecycle", "prepare"), ("ApprovalChannel", "open_lifecycle"),
            ("lifecycle", "start"), ("lifecycle", "attach_adopted"), ("lifecycle", "receive_rendezvous"),
            ("lifecycle", "submit_rendezvous"), ("lifecycle", "cold_step"), ("lifecycle", "cold_submit"),
            ("lifecycle", "finish_cold"), ("lifecycle", "adopted_step"), ("lifecycle", "adopted_submit"),
            ("lifecycle", "finish_adopted"), ("lifecycle", "close"), ("approval", "close"),
            ("channel", "close"), ("runtime", "close"))]
        self.assertEqual(ordered, sorted(ordered))
        forbidden = {"read_private", "signing_key", "from_private_bytes", "Popen", "execve", "system"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, forbidden)

    def test_each_transport_exchange_has_original_caps_and_actual_check_callback(self):
        tree = source()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in (
                    "open_lifecycle", "exchange_lifecycle"):
                kwargs = {item.arg: item.value for item in node.keywords}
                self.assertIsInstance(kwargs["check"], ast.Name)
                self.assertEqual(kwargs["check"].id, "current")
                self.assertEqual(kwargs["expires_at_unix_ns"].slice.value, "expiresAtUnixNanos")
                self.assertEqual(kwargs["deadline_boottime_ns"].slice.value,
                    "waitDeadlineBoottimeNs" if node.func.attr == "exchange_lifecycle" else "deadlineBoottimeNs")
        self.assertFalse(calls(tree, "channel", "check"))  # Final receipt permits real peer retirement.

    def test_selected_completion_transport_follows_actual_finish_before_continuing(self):
        tree = source()
        opened = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "open_lifecycle")
        self.assertIs(next(item.value.value for item in opened.keywords if item.arg == "completions"), True)
        completed = {node.args[0].value: node.lineno for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "complete"}
        self.assertEqual(set(completed), {"cold", "adopted"})
        self.assertLess(calls(tree, "lifecycle", "finish_cold")[0], completed["cold"])
        self.assertLess(completed["cold"], calls(tree, "lifecycle", "adopted_step")[0])
        self.assertLess(calls(tree, "lifecycle", "finish_adopted")[0], completed["adopted"])
        self.assertLess(completed["adopted"], calls(tree, "lifecycle", "close")[0])
        self.assertLess(calls(tree, "lifecycle", "completion_original")[0], calls(tree, "channel", "send_completion")[0])
        sent = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "send_completion")
        kwargs = {item.arg: item.value for item in sent.keywords}
        self.assertEqual(kwargs["check"].id, "completion_current")
        self.assertEqual(kwargs["deadline_boottime_ns"].slice.value, "waitDeadlineBoottimeNs")
        self.assertEqual(kwargs["expires_at_unix_ns"].slice.value, "expiresAtUnixNanos")

    def test_partial_error_owners_are_retained_inside_signal_ownership_guards(self):
        tree = source()
        guarded = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.With): continue
            for child in ast.walk(node):
                if (isinstance(child, ast.Assign) and isinstance(child.value, ast.Attribute)
                        and isinstance(child.value.value, ast.Name) and child.value.value.id == "error"
                        and child.value.attr == "owner"):
                    guarded.update(target.id for target in child.targets if isinstance(target, ast.Name))
        self.assertEqual(guarded, {"lifecycle", "channel"})
        pauses = calls(tree, "signal", "pause")
        self.assertEqual(len(pauses), 1)
        self.assertGreater(pauses[0], calls(tree, "lifecycle", "close")[0])

    def test_actual_result_pipe_reports_no_pilot_or_production_acceptance(self):
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        previous = os.dup(2)
        inheritable = os.get_inheritable(2)
        try:
            os.dup2(write_fd, 2, inheritable=False)
            self.assertTrue(cli._result("stopped-cleanup-complete", "synthetic-result-control", 66, 176,
                "sha256:" + "1" * 64))
            raw = os.read(read_fd, 4096)
        finally:
            os.dup2(previous, 2, inheritable=inheritable)
            for fd in (previous, write_fd, read_fd): os.close(fd)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 1)
        value = json.loads(raw)
        self.assertEqual(value["apiVersion"], cli.RESULT_API)
        self.assertIs(value["pilotAcceptanceVerified"], False)
        self.assertIs(value["productionReleaseEligible"], False)
        self.assertEqual(value["coldJobsCompleted"], 66)


if __name__ == "__main__":
    unittest.main()
