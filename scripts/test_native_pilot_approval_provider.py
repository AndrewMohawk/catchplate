#!/usr/bin/env python3
"""Closed invocation and public serializer controls, not provider execution.

The shared fixtures contain authentic synthetic signed sources and tiny inert
inventory trees. Approval serialization below proves only exact existing wire
fields, never an independent decision. No provider/channel owner, private key,
protected approval, successful validator or full 244-job lifecycle is mocked.
Source-order checks complement, and do not replace, actual process evidence.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from scripts import run_native_pilot_approval_provider as cli
from scripts import test_native_pilot_approval_policy as policy_fixture
from scripts import test_native_pilot_adopted_supervisor as adopted_fixture
from serverware import native_pilot_approval_provider as provider
from serverware import native_pilot_approval_install as approvals

p = provider.p


def arguments():
    result, descriptor = [cli.MODE], 3
    for name, kind in cli._PREFIX:
        result.extend(("--" + name, "sha256:" + "1" * 64 if kind == "sha" else str(descriptor)))
        if kind == "fd": descriptor += 1
    return result


def changed(flag, value):
    result = arguments(); result[result.index("--" + flag) + 1] = value
    return result


def methods():
    tree = ast.parse((ROOT / "serverware/native_pilot_approval_provider.py").read_text())
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ApprovalProvider")
    return {node.name: node for node in owner.body if isinstance(node, ast.FunctionDef)}


def calls(tree, name):
    return sorted(node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call)
        and ((isinstance(node.func, ast.Attribute) and node.func.attr == name)
            or (isinstance(node.func, ast.Name) and node.func.id == name)))


class ApprovalProviderControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="approval-provider-public-")
        cls.addClassCleanup(temporary.cleanup)
        cls.addClassCleanup(policy_fixture.source_fixture.runtime_fixture.thaw, Path(temporary.name))
        cls.source = policy_fixture.fixture(Path(temporary.name))

    def test_exact_five_public_sources_two_sockets_and_no_private_key_slot(self):
        value = cli._arguments(arguments())
        self.assertEqual(tuple(value), provider.FIELDS)
        self.assertEqual(tuple(name.replace("-", "_") for name in cli.INPUTS), provider.INPUTS)
        self.assertEqual(len(value), 12)
        self.assertEqual({item for name, item in value.items() if name.endswith("_fd")}, set(range(3, 10)))
        self.assertFalse(any("key" in name for name in value))

    def test_mode_flags_order_count_and_argument_types_are_closed(self):
        swapped = arguments(); swapped[1:5] = swapped[3:5] + swapped[1:3]
        for value in ([], tuple(arguments()), arguments()[1:], arguments()[:-2],
                arguments() + ["--authority-key-fd", "20"], swapped,
                ["--run-native-pilot-lifecycle"] + arguments()[1:],
                [cli.MODE, "--command"] + arguments()[2:]):
            with self.subTest(value=value[:2]), self.assertRaises(ValueError): cli._arguments(value)

    def test_descriptor_grammar_bounds_and_all_seven_aliases_refuse(self):
        for value in ("2", "03", "+3", "-3", "3.0", str(1 << 31), True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cli._arguments(changed("policy-fd", value))
        for flag, kind in cli._PREFIX:
            if kind == "fd" and flag != "policy-fd":
                with self.subTest(flag=flag), self.assertRaises(ValueError):
                    cli._arguments(changed(flag, "3"))

    def test_external_hashes_are_exact_lowercase_pins(self):
        for flag, kind in cli._PREFIX:
            if kind != "sha": continue
            for value in ("1" * 64, "sha256:" + "A" * 64, "sha256:" + "1" * 63,
                    "sha256:" + "1" * 65, "sha256:" + "g" * 64):
                with self.subTest(flag=flag, value=value), self.assertRaises(ValueError):
                    cli._arguments(changed(flag, value))

    def test_rendezvous_serializer_preserves_exact_request_pins_and_bounds(self):
        source = self.source["source"]
        candidate = policy_fixture.source_fixture.rendezvous(source)
        raw = candidate["input_original"]
        request = provider.rendezvous.verify_request(source["request_raw"])
        approval_raw = provider._approval("rendezvous", source["request_raw"], raw)
        expected = dict(apiVersion=provider.rendezvous.APPROVAL_API,
            requestSha256=p.sha(source["request_raw"]), inputSha256=p.sha(raw),
            **{name: request[name] for name in provider.rendezvous.PINS + provider.rendezvous.BOUNDS})
        self.assertEqual(approval_raw, p.canonical(expected))
        provider.rendezvous.approval(approval_raw, request_raw=source["request_raw"], input_sha256=p.sha(raw))

    def test_cold_serializer_uses_existing_handoff_approval_not_new_authority(self):
        prepared = policy_fixture.prepare(self.source)
        _, request_raw = provider.cold_wire.request(sequence=1, job="closure-set",
            deadline=prepared["startupDeadline"], observation={}, previous=None, handoff=True)
        # A literal signed fixture source only exercises pin serialization;
        # _approval intentionally is not the producer's semantic validator.
        raw = self.source["source"]["recipe"]["assignmentOriginal"].encode("ascii")
        request = p.document(request_raw, provider.cold_wire.MAX_REQUEST)
        expected = dict(apiVersion=provider.cold_wire.HANDOFF_APPROVAL_API,
            requestSha256=p.sha(request_raw), inputSha256=p.sha(raw),
            **{name: request[name] for name in ("sequence", "job", "deadlineBoottimeNs")})
        result = provider._approval("cold", request_raw, raw)
        self.assertEqual(result, p.canonical(expected))
        provider.cold_wire.approval(result, request_raw=request_raw, input_sha256=p.sha(raw))
        legacy = dict(request, apiVersion=provider.cold_wire.REQUEST_API)
        with self.assertRaises(ValueError): provider._approval("cold", p.canonical(legacy), raw)

    def test_adopted_serializer_matches_existing_exact_approval2_validator(self):
        pending = adopted_fixture.pending()
        input_raw = b'{"synthetic":"wire-only input"}'
        before = copy.deepcopy(pending)
        result = provider._approval("adopted", pending, input_raw)
        request_raw = pending["requestOriginal"].encode("ascii")
        request = p.document(request_raw, provider.wire.MAX_REQUEST)
        expected = adopted_fixture.approval(request, input_raw)
        self.assertEqual(result, p.canonical(expected))
        checked = approvals._prepare_adopted(request_raw, result, input_raw, p.sha(result), p.sha(input_raw),
            now_boottime_ns=1400, now_unix_ns=8000)
        self.assertEqual(checked[2:], (5000, 9000))
        self.assertEqual(pending, before)

    def test_all_eight_current_heads_refuse_provider_approval_serialization(self):
        self.assertEqual(len(provider.heads.JOB_NAMES), 8)
        for index in provider.heads.INDICES:
            pending = adopted_fixture.pending(index)
            with self.subTest(job=pending["job"]), self.assertRaises(ValueError):
                provider._approval("adopted", pending, b"{}")
        for stage in ("bootstrap", "adopted-completion", "unknown"):
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                provider._approval(stage, adopted_fixture.pending(), b"{}")

    def test_public_admission_and_independent_authorization_precede_approval_and_seal(self):
        selected = methods()
        delegated = selected["_delegated_pair"]
        authorized, prepared = calls(delegated, "_authorize"), calls(delegated, "prepare")
        approved, sealed = calls(delegated, "_approval"), calls(delegated, "open")
        self.assertEqual(len(authorized), 3)
        self.assertLess(authorized[0], prepared[0])
        self.assertLess(prepared[0], authorized[1])
        self.assertLess(authorized[1], approved[0])
        self.assertLess(approved[0], sealed[0])
        self.assertLess(sealed[0], authorized[2])
        external = selected["_head_pair"]
        self.assertFalse(calls(external, "_approval"))
        sequence = [calls(external, name)[0] for name in
            ("current_head_evidence", "exchange_current_head", "selection", "prepare", "require_candidate")]
        self.assertEqual(sequence, sorted(sequence))
        exchange = next(node for node in ast.walk(external) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "exchange_current_head")
        evidence = next(item.value for item in exchange.keywords if item.arg == "evidence_original")
        self.assertEqual(ast.unparse(evidence), "evidence")
        self.assertLess(calls(external, "_authorize")[0], sequence[0])
        self.assertLess(sequence[0], calls(external, "_authorize")[1])
        self.assertLess(calls(external, "_authorize")[1], sequence[1])
        for name in ("signing_key", "from_private_bytes", "Popen", "execve", "system"):
            self.assertFalse(any(calls(node, name) for node in selected.values()))

    def test_actual_receipts_precede_transcript_accept_and_completion_acknowledgement(self):
        selected = methods()["run"]
        self.assertLess(calls(selected, "respond_lifecycle")[0], calls(selected, "accept")[0])
        self.assertLess(calls(selected, "receive_completion")[0], calls(selected, "complete")[0])
        self.assertLess(calls(selected, "complete")[0], calls(selected, "acknowledge_completion")[0])
        self.assertEqual(len(provider.wire.ORDER), 244)
        self.assertEqual(provider.wire.completion_stage(68, 0), "cold")
        self.assertEqual(provider.wire.completion_stage(244, 1), "adopted")

    def test_original_listener_header_is_distinct_from_tighter_decision_caps(self):
        prepared = policy_fixture.prepare(self.source)
        source = self.source["source"]
        deadline = p.ns(source["listener"]["window"]["lifetimeDeadlineBoottimeNs"])
        expiry = source["listener"]["expiresAtUnixNanos"]
        self.assertLess(prepared["epochLimit"], expiry)
        header, _, _ = provider.wire.request("bootstrap", source["pending"], 0,
            deadline_boottime_ns=deadline, expires_at_unix_ns=expiry,
            context={}, boot=source["clocks"]["boot"],
            now_boottime_ns=source["clocks"]["now_boottime_ns"], completions=True)
        provider.wire.header(header, 0, deadline_boottime_ns=deadline,
            expires_at_unix_ns=expiry, completions=True)
        # Original wire framing remains exact. The provider must not require
        # its independent policy's tighter cap to replace this unseen header.
        with self.assertRaises(ValueError):
            provider.wire.header(header, 0, deadline_boottime_ns=prepared["deadline"],
                expires_at_unix_ns=prepared["epochLimit"], completions=True)
        selected = methods()
        for method, expected in (("run", "_transport_caps"), ("check", "_prepared")):
            assigned = [node.value for node in ast.walk(selected[method]) if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "caps" for target in node.targets)]
            self.assertEqual(len(assigned), 1)
            self.assertIsInstance(assigned[0], ast.Attribute)
            self.assertEqual(assigned[0].attr, expected)
        for node in ast.walk(selected["run"]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in (
                    "receive_lifecycle", "receive_completion"):
                callback = next(item.value for item in node.keywords if item.arg == "check")
                self.assertEqual(ast.unparse(callback), "self.check")


if __name__ == "__main__":
    unittest.main()
