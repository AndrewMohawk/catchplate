#!/usr/bin/env python3
"""Pure CLI/wire controls, not approval provenance or a live cold assembly.

No key, root file, process-owner substitute or service is created by this suite.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
import native_pilot_authority_runtime_entrypoint as entry
from serverware import native_pilot_genesis_authority as cli
from serverware import native_pilot_genesis_authority_channel as channel
from serverware import native_pilot_genesis_execution_protocol as protocol
from serverware import native_pilot_genesis_jobs as jobs

p = protocol.p


def arguments():
    result = ["--run-native-genesis", "--supervisor-inventory-fd", "3",
        "--supervisor-inventory-sha256", p.sha(b"synthetic package inventory"),
        "--genesis-configuration-fd", "4", "--genesis-configuration-sha256", p.sha(b"synthetic configuration")]
    for purpose in jobs.KEY_PURPOSES:
        result.extend(("--authority-key", purpose + "=5"))
    return result


def request():
    return protocol.request(sequence=1, job=jobs.JOBS[0].name, deadline=10_000,
        observation={"synthetic.original": b'{"counter":18446744073709551615}'}, previous=None)


def answer(raw):
    return dict(apiVersion=channel.REPLY_API, sequence=1, job=jobs.JOBS[0].name,
        requestSha256=p.sha(raw), inputSha256=p.sha(b"synthetic input"), approvalSha256=p.sha(b"synthetic approval"))


class GenesisAuthorityTests(unittest.TestCase):
    def test_exact_cold_keys_and_distinct_public_fds_with_shared_selected_key(self):
        value = cli.arguments(arguments())
        self.assertEqual(tuple(value["authority_key_fds"]), jobs.KEY_PURPOSES)
        self.assertEqual(set(value["authority_key_fds"].values()), {5})
        self.assertEqual((value["supervisor_inventory_fd"], value["genesis_configuration_fd"]), (3, 4))
        self.assertTrue(entry.valid_arguments(arguments()))

    def test_handoff_cli_requires_separate_inherited_channel(self):
        values = arguments()
        values[0] = "--run-native-genesis-handoff"
        values[9:9] = ["--core-handoff-fd", "6"]
        selected = cli.arguments(values)
        self.assertTrue(selected["handoff"])
        self.assertEqual(selected["core_handoff_fd"], 6)
        self.assertTrue(entry.valid_arguments(values))
        for fd in ("3", "4", "5", "06", "2"):
            changed = list(values); changed[10] = fd
            with self.subTest(fd=fd), self.assertRaises(ValueError): cli.arguments(changed)
        changed = list(values); changed[0] = "--run-native-genesis"
        self.assertFalse(entry.valid_arguments(changed))
        with self.assertRaises(ValueError): cli.arguments(changed)
        changed = arguments(); changed[0] = "--run-native-genesis-handoff"
        self.assertFalse(entry.valid_arguments(changed))
        with self.assertRaises(ValueError): cli.arguments(changed)

    def test_handoff_reply_requires_matching_profile_and_fixed_paths(self):
        value, raw = protocol.request(sequence=66, job="handoff-cold-core", deadline=10_000,
            observation={}, previous=None, handoff=True)
        reply = dict(apiVersion=channel.HANDOFF_REPLY_API, sequence=66, job=value["job"], requestSha256=p.sha(raw),
            inputSha256=p.sha(b"input"), approvalSha256=p.sha(b"approval"))
        self.assertEqual(channel.reply(p.canonical(reply), raw), reply)
        with self.assertRaises(ValueError):
            channel.reply(p.canonical({**reply, "apiVersion": channel.REPLY_API}), raw)
        for name in ("acquire-cold-core", "handoff-cold-core"):
            with self.assertRaises(ValueError): channel.paths(name)
            self.assertEqual(channel.paths(name, handoff=True)[0], channel.APPROVAL_ROOT + "/" + name + ".input.json")

    def test_cold_invocation_refuses_alias_missing_extra_or_unknown_purpose(self):
        bad = [arguments()[:-2], arguments() + ["--help"], tuple(arguments()), []]
        for index, value in ((2, "4"), (6, "3"), (10, jobs.KEY_PURPOSES[0] + "=3"),
                (10, jobs.KEY_PURPOSES[0] + "=4"), (10, "unknown=5"), (10, jobs.KEY_PURPOSES[1] + "=5"),
                (10, jobs.KEY_PURPOSES[0] + "=5=6")):
            altered = arguments(); altered[index] = value; bad.append(altered)
        for values in bad:
            with self.subTest(values=values[:11]), self.assertRaises(ValueError):
                cli.arguments(values)

    def test_canonical_numeric_and_digest_syntax(self):
        for index, replacement in ((2, "03"), (2, "+3"), (2, "2"), (6, str(1 << 31)),
                (4, "sha256:" + "A" * 64), (8, "1" * 64), (10, jobs.KEY_PURPOSES[0] + "=05"),
                (10, jobs.KEY_PURPOSES[0] + "=" + str(1 << 31))):
            values = arguments(); values[index] = replacement
            with self.subTest(index=index, value=replacement), self.assertRaises(ValueError):
                cli.arguments(values)

    def test_bootstrap_keeps_hot_profile_separate_from_explicit_cold_profile(self):
        hot = ["--run-native-pilot", "--runtime-inventory-fd", "3",
            "--runtime-inventory-sha256", p.sha(b"hot inventory"), "--authority-key", "driver-bootstrap=4"]
        self.assertTrue(entry.valid_arguments(hot))
        self.assertFalse(entry.valid_arguments(hot + ["--genesis-configuration-fd", "5"]))
        cold = arguments(); cold[0] = "--run-native-pilot"
        self.assertFalse(entry.valid_arguments(cold))
        for values in (hot[:-1], hot + ["--module", "arbitrary"], tuple(hot), [None]):
            self.assertFalse(entry.valid_arguments(values))

    def test_exact_request_reply_and_literal_u64_observation(self):
        value, raw = request()
        self.assertEqual(value["observation"]["synthetic.original"], '{"counter":18446744073709551615}')
        reply = answer(raw)
        self.assertEqual(channel.reply(p.canonical(reply), raw), reply)
        self.assertEqual(set(reply), {"apiVersion", "sequence", "job", "requestSha256", "inputSha256", "approvalSha256"})

    def test_no_reply_substitution_future_job_or_supplied_path(self):
        _, raw = request()
        for field, value in (("apiVersion", "serverware.nativePilotAuthorityJobReply/v1"),
                ("sequence", 2), ("sequence", True), ("job", jobs.JOBS[1].name),
                ("requestSha256", p.sha(b"another request")), ("inputSha256", "sha256:" + "x" * 64),
                ("approvalSha256", "sha256:" + "A" * 64), ("path", "/tmp/approval.json")):
            changed = answer(raw); changed[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                channel.reply(p.canonical(changed), raw)
        with self.assertRaises(ValueError):
            channel.reply(p.canonical(answer(raw)) + b"\n", raw)

    def test_only_catalogue_jobs_have_fixed_cold_paths(self):
        for selected in jobs.JOBS:
            source, approval = channel.paths(selected.name)
            self.assertEqual(source, channel.APPROVAL_ROOT + "/" + selected.name + ".input.json")
            self.assertEqual(approval, channel.APPROVAL_ROOT + "/" + selected.name + ".approval.json")
        for name in ("../escape", "/tmp/input", "", "shutdown", None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                channel.paths(name)

    def test_actual_approval_original_must_bind_all_request_fields_and_input(self):
        ticket, raw = request()
        value = dict(apiVersion=protocol.APPROVAL_API, sequence=ticket["sequence"], job=ticket["job"],
            requestSha256=p.sha(raw), inputSha256=p.sha(b"input"), deadlineBoottimeNs=ticket["deadlineBoottimeNs"])
        self.assertEqual(protocol.approval(p.canonical(value), request_raw=raw, input_sha256=value["inputSha256"]), value)
        for field, replacement in (("sequence", 2), ("job", jobs.JOBS[1].name), ("deadlineBoottimeNs", "10001"),
                ("requestSha256", p.sha(b"other request")), ("inputSha256", p.sha(b"other input")), ("retry", True)):
            altered = copy.deepcopy(value); altered[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                protocol.approval(p.canonical(altered), request_raw=raw, input_sha256=value["inputSha256"])

    def test_source_runtime_admission_precedes_keys_and_cleanup_precedes_capability_close(self):
        tree = ast.parse((ROOT / "serverware/native_pilot_genesis_authority.py").read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        calls = {ast.unparse(node.func): node.lineno for node in ast.walk(main) if isinstance(node, ast.Call)}
        self.assertLess(calls["runtime.admit"], calls["executor.prepare_keys"])
        self.assertLess(calls["executor.close"], calls["channel.close"])
        self.assertLess(calls["channel.close"], calls["runtime.close"])
        self.assertIn("signal.pause", calls)
        self.assertNotIn("subprocess.run", calls)


if __name__ == "__main__":
    unittest.main()
