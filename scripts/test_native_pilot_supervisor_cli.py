#!/usr/bin/env python3
"""Pure CLI grammar and source-order controls, never a fabricated live owner."""
from __future__ import annotations

import ast
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))
import run_native_pilot_supervisor as cli
from serverware.native_pilot_phase_execution import KEY_PURPOSES


def arguments():
    values = {
        "supervisor-inventory-fd": "3", "policy-fd": "4", "recipe-fd": "5",
        "conductor-inventory-fd": "6", "authority-inventory-fd": "7", "approval-fd": "8",
        "approval-peer-pid": "9000", "approval-peer-uid": "0", "approval-peer-gid": "0",
    }
    result = ["--run-native-pilot"]
    for flag, kind in cli._PREFIX:
        result += ["--" + flag, "sha256:" + "1" * 64 if kind == "sha" else values[flag]]
    for purpose in KEY_PURPOSES:
        result += ["--authority-key", purpose + "=9"]
    return result


def changed(flag, value):
    result = arguments()
    result[result.index("--" + flag) + 1] = value
    return result


def source():
    return ast.parse((SCRIPTS / "run_native_pilot_supervisor.py").read_text())


class SupervisorCliControls(unittest.TestCase):
    def test_exact_113_selectors_allow_actual_shared_key_descriptor(self):
        self.assertEqual(len(KEY_PURPOSES), 113)
        value = cli._arguments(arguments(), KEY_PURPOSES)
        self.assertEqual(tuple(value["authority_key_fds"]), KEY_PURPOSES)
        self.assertEqual(set(value["authority_key_fds"].values()), {9})
        self.assertEqual((value["supervisor_inventory_fd"], value["approval_fd"]), (3, 8))
        self.assertEqual(len(arguments()), 255)

    def test_numeric_arguments_are_canonical_and_bounded(self):
        for flag, value in (("policy-fd", "03"), ("policy-fd", "+3"), ("policy-fd", "2"),
                ("policy-fd", str(1 << 31)), ("approval-peer-pid", "1"),
                ("approval-peer-uid", "-1"), ("approval-peer-gid", str((1 << 32) - 1))):
            with self.subTest(flag=flag, value=value), self.assertRaises(ValueError):
                cli._arguments(changed(flag, value), KEY_PURPOSES)

    def test_each_original_pin_is_literal_lowercase_sha256(self):
        for flag, kind in cli._PREFIX:
            if kind == "sha":
                for value in ("sha256:" + "A" * 64, "sha256:" + "1" * 63, "1" * 64):
                    with self.subTest(flag=flag, value=value), self.assertRaises(ValueError):
                        cli._arguments(changed(flag, value), KEY_PURPOSES)

    def test_no_extra_missing_or_reordered_prefix(self):
        reordered = arguments()
        reordered[1:5] = reordered[3:5] + reordered[1:3]
        unknown = arguments(); unknown[1] = "--module"
        for value in (arguments() + ["--help"], arguments()[1:], arguments()[:-2], reordered, unknown):
            with self.subTest(value=value[:5]), self.assertRaises(ValueError):
                cli._arguments(value, KEY_PURPOSES)

    def test_purpose_names_and_order_are_closed(self):
        offset = 1 + 2 * len(cli._PREFIX)
        for literal in ("unknown=9", KEY_PURPOSES[1] + "=9", KEY_PURPOSES[0] + "=09",
                KEY_PURPOSES[0] + "=9=10"):
            value = arguments(); value[offset + 1] = literal
            with self.subTest(literal=literal), self.assertRaises(ValueError):
                cli._arguments(value, KEY_PURPOSES)

    def test_public_and_channel_descriptors_cannot_alias_keys_or_each_other(self):
        with self.assertRaises(ValueError):
            cli._arguments(changed("approval-fd", "3"), KEY_PURPOSES)
        offset = 1 + 2 * len(cli._PREFIX)
        for fd in range(3, 9):
            value = arguments(); value[offset + 1] = KEY_PURPOSES[0] + "=" + str(fd)
            with self.subTest(fd=fd), self.assertRaises(ValueError):
                cli._arguments(value, KEY_PURPOSES)

    def test_source_admits_self_and_scope_before_fixed_child_start(self):
        tree = source()
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        calls = {ast.unparse(node.func): node.lineno for node in ast.walk(main) if isinstance(node, ast.Call)}
        self.assertLess(calls["runtime.admit"], calls["AuthorityCoordinatorProcess.prepare"])
        self.assertLess(calls["runtime.require_inventory_sources"], calls["AuthorityCoordinatorProcess.prepare"])
        self.assertLess(calls["require_complete_coverage"], calls["supervisor.start"])
        self.assertLess(calls["policy.require_final_scope"], calls["supervisor.start"])
        loops = [node for node in ast.walk(main) if isinstance(node, ast.For)
            and ast.unparse(node.iter) == "SUPPORTED_JOBS"]
        self.assertEqual(len(loops), 1)
        self.assertEqual(ast.unparse(loops[0].target), "(phase, job)")
        self.assertNotIn("channel.check", {ast.unparse(node.func) for node in ast.walk(loops[0])
            if isinstance(node, ast.Call)})

    def test_source_late_fd_intake_and_unknown_cleanup_never_fabricate_success(self):
        tree = source()
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        calls = {ast.unparse(node.func) for node in ast.walk(main) if isinstance(node, ast.Call)}
        self.assertIn("channel.exchange", calls)
        self.assertIn("approval.resume_kwargs", calls)
        self.assertIn("supervisor.resume_current_head", calls)
        self.assertNotIn("installation.install", calls)
        self.assertNotIn("_approval", calls)
        terminal_try = next(node for node in main.body if isinstance(node, ast.Try)
            and any(isinstance(item, ast.If) and ast.unparse(item.test) == "supervisor is not None"
                    for item in node.body))
        terminal_calls = sorted((node.lineno, ast.unparse(node.func)) for node in ast.walk(terminal_try)
            if isinstance(node, ast.Call))
        first_line = {name: line for line, name in terminal_calls}
        self.assertLess(first_line["supervisor.close"], first_line["policy.close"])
        self.assertLess(first_line["process.close"], first_line["policy.close"])
        self.assertLess(first_line["policy.close"], first_line["approval.close"])
        handler = terminal_try.handlers[0]
        self.assertTrue(any(isinstance(node, ast.While) and isinstance(node.test, ast.Constant)
            and node.test.value is True for node in handler.body))
        self.assertTrue(any(isinstance(node, ast.Call) and ast.unparse(node.func) == "signal.pause"
            for node in ast.walk(handler)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
