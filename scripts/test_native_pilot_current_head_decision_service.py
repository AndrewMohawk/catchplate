#!/usr/bin/env python3
"""Pure service admission joins, never independent freshness or live custody.

Existing signed synthetic histories authenticate the complete Input3 sources.
Test-only decisions/approvals do not establish operator authority. No service,
directory, provider or full lifecycle owner is fabricated or mocked here.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from scripts.test_native_pilot_approval_current_heads import fixture
from serverware import native_pilot_current_head_decision_service_profile as profile
from serverware import native_pilot_supervisor_current_head_profile as evidence_profile

p = profile.p
ERRORS = (ValueError, KeyError, TypeError, InvalidSignature)


def source(name=None):
    value = fixture(name)
    value["evidence_raw"] = evidence_profile.observed_original(value["name"], value["source"]["context"])
    return value


def checked(value, **clocks):
    return profile.require_pair(value["pending"], value["evidence_raw"], value["input_raw"], value["approval_raw"],
        **(value["clocks"] | clocks))


def configuration(value):
    boot = value["clocks"]["boot"]
    return dict(apiVersion=profile.API, purpose=profile.PURPOSE,
        supervisorInventorySha256=p.sha(b"synthetic installed inventory pin"),
        providerPeer=dict(pid=1234, uid=0, gid=0, startTimeTicks=456), directory=dict(device=21, inode=22),
        **dict(zip(profile.FIELDS[5:8], boot, strict=True)), issuedAtBoottimeNs="1", deadlineBoottimeNs="5000",
        issuedAtUnixNanos=1, expiresAtUnixNanos=9000)


def admitted(value, config=None, **clocks):
    config = configuration(value) if config is None else config
    return profile.configuration(p.canonical(config), inventory_sha256=configuration(value)["supervisorInventorySha256"],
        **(value["clocks"] | clocks))


class CurrentHeadDecisionServiceControls(unittest.TestCase):
    def test_fixed_configuration_pins_namespace_peer_directory_and_original_caps(self):
        value = source()
        result = admitted(value)
        self.assertEqual((result["deadline"], result["epochLimit"]), (5000, 9000))
        self.assertEqual(result["value"], configuration(value))
        for update in ({"apiVersion": "other"}, {"purpose": "approve-history"},
                {"supervisorInventorySha256": p.sha(b"other")}, {"directory": {"device": 1}},
                {"providerPeer": dict(pid=1234, uid=1, gid=0, startTimeTicks=456)}, {"path": "/tmp/decisions"}):
            with self.subTest(update=update), self.assertRaises(ERRORS):
                admitted(value, configuration(value) | update)

    def test_original_limits_and_canonical_config_cannot_be_renewed(self):
        value = source()
        for clocks in ({"now_boottime_ns": 5000}, {"now_unix_ns": 9000},
                {"boot": (value["clocks"]["boot"][0], 1, 999)}, {"now_unix_ns": True}):
            with self.subTest(clocks=clocks), self.assertRaises(ERRORS): admitted(value, **clocks)
        config = configuration(value)
        with self.assertRaises(ERRORS): profile.configuration(b" " + p.canonical(config),
            inventory_sha256=config["supervisorInventorySha256"], **value["clocks"])

    def test_exact_eight_closed_filename_sets_and_fixed_directory(self):
        names = {name for job in profile.intake.JOB_NAMES for name in profile.filenames(job).values()}
        self.assertEqual(len(names), 32)
        self.assertEqual(profile.DIRECTORY, "/etc/serverware/native-pilot-current-head-decisions")
        self.assertTrue(all("/" not in name and name.endswith(".json") for name in names))
        for job in ("../current-head", "stop", "*", ""):
            with self.subTest(job=job), self.assertRaises(ERRORS): profile.filenames(job)

    def test_all_eight_full_signed_input_sources_match_actual_evidence(self):
        for name in profile.intake.JOB_NAMES:
            value = source(name); before = copy.deepcopy(value)
            with self.subTest(name=name):
                bounds = checked(value)
                self.assertLessEqual(bounds["deadline"], 5000)
                self.assertEqual(bounds["epochLimit"], 9000)
                self.assertEqual(value, before)

    def test_evidence_cannot_replace_complete_input_originals(self):
        for name in ("driverConfiguration", "driverWindow", "launch", "preparation", "resources", "configuration",
                "primaryInitialHistory"):
            value = source(); evidence = p.document(value["evidence_raw"], evidence_profile.MAX_OBSERVED)
            evidence["originals"][name] += " "
            value["evidence_raw"] = p.canonical(evidence)
            with self.subTest(name=name), self.assertRaises(ERRORS): checked(value)
        value = source(); evidence = p.document(value["evidence_raw"], evidence_profile.MAX_OBSERVED)
        evidence["rootAuthority"]["keyId"] = p.sha(b"different root")
        value["evidence_raw"] = p.canonical(evidence)
        with self.assertRaises(ERRORS): checked(value)

    def test_approval_and_fresh_decision_must_be_supplied_not_inferred(self):
        for field in ("approval_raw", "input_raw"):
            value = source(); value[field] = b"{}"
            with self.subTest(field=field), self.assertRaises(ERRORS): checked(value)
        value = source(); approved = p.document(value["approval_raw"], profile.intake.MAX_APPROVAL)
        approved["inputSha256"] = p.sha(b"unapproved source")
        value["approval_raw"] = p.canonical(approved)
        with self.assertRaises(ERRORS): checked(value)
        value = source(); supplied = p.document(value["input_raw"], profile.intake.MAX_INPUT)
        del supplied["currentness"]; value["input_raw"] = p.canonical(supplied)
        approved = p.document(value["approval_raw"], profile.intake.MAX_APPROVAL)
        approved["inputSha256"] = p.sha(value["input_raw"]); value["approval_raw"] = p.canonical(approved)
        with self.assertRaises(ERRORS): checked(value)

    def test_actual_request_selected_history_and_authority_substitution_refuse(self):
        for change in ("job", "nonce", "history", "authority"):
            value = source(); evidence = p.document(value["evidence_raw"], evidence_profile.MAX_OBSERVED)
            if change == "job": evidence["jobName"] = profile.intake.JOB_NAMES[-1]
            elif change == "nonce": evidence["requestNonceSha256"] = p.sha(b"other request")
            elif change == "history": evidence["originals"]["selectedInitialHistory"] += " "
            else: evidence["checkpointAuthority"]["keyId"] = p.sha(b"other authority")
            value["evidence_raw"] = p.canonical(evidence)
            with self.subTest(change=change), self.assertRaises(ERRORS): checked(value)

    def test_selected_service_source_forwards_only_after_pair_validation(self):
        tree = ast.parse((ROOT / "serverware/native_pilot_current_head_decision_service.py").read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "CurrentHeadDecisionService")
        methods = {node.name: node for node in owner.body if isinstance(node, ast.FunctionDef)}
        calls = [(node.func.attr, node.lineno) for node in ast.walk(methods["run"])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        def position(name): return min(line for method, line in calls if method == name)
        self.assertLess(position("receive_current_head"), position("_publish"))
        self.assertLess(position("_publish"), position("_read"))
        self.assertLess(position("_read"), position("require_pair"))
        self.assertLess(position("require_pair"), position("respond_current_head"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, ("sign", "signing_key", "from_private_bytes", "unlink"))
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    self.assertNotIn(node.func.attr, ("remove", "rmdir"))
        # Callback checks the actual local owner, never recursively the channel.
        self.assertNotIn("self._peer", ast.unparse(methods["check"]))

    def test_receiver_publishes_complete_final_names_through_retained_atomic_owner(self):
        tree = ast.parse((ROOT / "serverware/native_pilot_current_head_decision_service.py").read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "CurrentHeadDecisionService")
        methods = {node.name: node for node in owner.body if isinstance(node, ast.FunctionDef)}
        publish = ast.unparse(methods["_publish"])
        self.assertIn("self._atomic.publish(name, raw)", publish)
        self.assertNotIn("os.write", publish)
        self.assertNotIn("os.O_CREAT", publish)
        self.assertLess(publish.index("self._atomic.publish"), publish.index("self._read"))
        self.assertIn("owner._atomic = error.owner", ast.unparse(methods["open"]))
        self.assertIn("self._atomic.close()", ast.unparse(methods["close"]))


if __name__ == "__main__":
    unittest.main()
