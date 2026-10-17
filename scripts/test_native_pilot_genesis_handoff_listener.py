#!/usr/bin/env python3
"""Pure pre-job listener grammar/approval controls, not a live ceremony.

No listener, process/PIDFD owner, protected original, received core, key,
signature or successful cleanup is fabricated. Public requests below are
synthetic inputs to byte-association checks, not evidence of an actual sender.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import native_pilot_authority_runtime_entrypoint as entry
from catchplate import native_pilot_genesis_authority as authority
from catchplate import native_pilot_genesis_handoff_listener as listener
from catchplate import native_pilot_genesis_jobs as jobs
from catchplate import native_pilot_genesis_execution_protocol as execution


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def fixture():
    value = {"apiVersion": "catchplate.nativePilotGenesisListenerConfiguration/v1", "window": {
        "bootIdBase64url": "AAECAwQFBgcICQoLDA0ODw", "timeNamespaceDevice": 11, "timeNamespaceInode": 12,
        "issuedAtBoottimeNs": "1000000000", "startupDeadlineBoottimeNs": "2000000000",
        "lifetimeDeadlineBoottimeNs": "4000000000", "invocationId": "1234567890abcdef1234567890abcdef"},
        "expiresAtUnixNanos": 9000000000}
    clocks = dict(boot=(value["window"]["bootIdBase64url"], 11, 12), now_boottime_ns=1500000000, now_unix_ns=8000000000)
    return value, clocks


def arguments():
    result = ["--run-native-genesis-listener", "--supervisor-inventory-fd", "3",
        "--supervisor-inventory-sha256", sha(b"synthetic inventory"), "--genesis-listener-configuration-fd", "4",
        "--genesis-listener-configuration-sha256", sha(b"synthetic listener configuration")]
    for purpose in jobs.KEY_PURPOSES:
        result += ["--authority-key", purpose + "=5"]
    return result


def request():
    return canonical(dict(apiVersion=listener.REQUEST_API, sequence=0, listenerOriginal="{}",
        listenerSha256=sha(b"{}"), configurationSha256=sha(b"synthetic listener configuration"),
        deadlineBoottimeNs="2000000000", expiresAtUnixNanos=9000000000))


class GenesisHandoffListenerControls(unittest.TestCase):
    def test_no_predicted_peer_is_present_in_listener_configuration(self):
        value, clocks = fixture()
        self.assertEqual(listener.configuration(canonical(value), **clocks), value)
        self.assertNotIn("coreHandoff", value)
        with self.assertRaises(ValueError):
            listener.configuration(canonical(value | {"coreHandoff": {"peerPid": 123, "peerUid": 0, "peerGid": 0}}), **clocks)
        self.assertEqual(listener.ENDPOINT, "/run/catchplate/native-pilot-core-handoff/core.sock")

    def test_late_configuration_requires_existing_handoff_profile_and_exact_original_bounds(self):
        value, clocks = fixture()
        selected = value | {"apiVersion": execution.HANDOFF_CONFIGURATION_API,
            "coreHandoff": {"peerPid": 123, "peerUid": 0, "peerGid": 0}}
        self.assertEqual(listener.require_execution(canonical(selected), value, **clocks), selected)
        for changed in (selected | {"apiVersion": execution.CONFIGURATION_API},
                selected | {"expiresAtUnixNanos": value["expiresAtUnixNanos"] + 1},
                selected | {"expiresAtUnixNanos": value["expiresAtUnixNanos"] - 1},
                selected | {"window": value["window"] | {"startupDeadlineBoottimeNs": "2100000000"}},
                selected | {"coreHandoff": {"peerPid": 123, "peerUid": 1000, "peerGid": 0}}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                listener.require_execution(canonical(changed), value, **clocks)

    def test_listener_admission_preserves_boot_original_startup_and_expiry(self):
        value, clocks = fixture()
        for altered in (clocks | {"now_boottime_ns": 999999999}, clocks | {"now_boottime_ns": 2000000000},
                clocks | {"now_unix_ns": 9000000000}, clocks | {"boot": (clocks["boot"][0], 12, 11)}):
            with self.subTest(clocks=altered), self.assertRaises(ValueError):
                listener.configuration(canonical(value), **altered)
        with self.assertRaises(ValueError):
            listener.configuration(canonical(value | {"window": value["window"] | {"startupDeadlineBoottimeNs": "32000000000"}}), **clocks)

    def test_listener_cli_is_separate_without_inherited_peer_socket(self):
        values = arguments()
        selected = authority.arguments(values)
        self.assertTrue(selected["handoff"]); self.assertTrue(selected["listener"])
        self.assertEqual(selected["genesis_listener_configuration_fd"], 4)
        self.assertNotIn("core_handoff_fd", selected)
        self.assertEqual(tuple(selected["authority_key_fds"]), jobs.KEY_PURPOSES)
        self.assertTrue(entry.valid_arguments(values))
        for altered in (["--run-native-genesis", *values[1:]], ["--run-native-genesis-handoff", *values[1:]],
                values[:9] + ["--core-handoff-fd", "6"] + values[9:], values[:-2],
                values[:5] + ["--genesis-configuration-fd", *values[6:]]):
            with self.subTest(arguments=altered), self.assertRaises(ValueError): authority.arguments(altered)
        self.assertEqual((len(jobs.JOBS), len(jobs.HANDOFF_JOBS), len(jobs.KEY_PURPOSES)), (64, 66, 36))

    def test_prejob_reply_binds_exact_request_and_public_file_hashes(self):
        raw = request()
        value = dict(apiVersion=listener.REPLY_API, requestSha256=sha(raw), inputSha256=sha(b"input"), approvalSha256=sha(b"approval"))
        self.assertEqual(listener.reply(canonical(value), raw), value)
        for changed in (value | {"requestSha256": sha(b"other")}, value | {"apiVersion": "catchplate.nativePilotGenesisJobReply/v2"},
                value | {"path": "/tmp/caller-input"}, value | {"inputSha256": "unknown"}):
            with self.subTest(value=changed), self.assertRaises(ValueError): listener.reply(canonical(changed), raw)
        changed_request = json.loads(raw); changed_request["sequence"] = 1
        with self.assertRaises(ValueError): listener.reply(canonical(value), canonical(changed_request))

    def test_prejob_independent_approval_cannot_renew_or_substitute_sources(self):
        raw = request(); selected = json.loads(raw)
        value = dict(apiVersion=listener.APPROVAL_API, requestSha256=sha(raw), inputSha256=sha(b"input"),
            listenerConfigurationSha256=selected["configurationSha256"], deadlineBoottimeNs=selected["deadlineBoottimeNs"],
            expiresAtUnixNanos=selected["expiresAtUnixNanos"])
        self.assertEqual(listener.approval(canonical(value), request_raw=raw, input_sha256=sha(b"input")), value)
        for fields in ({"requestSha256": sha(b"other")}, {"inputSha256": sha(b"other")},
                {"listenerConfigurationSha256": sha(b"other")}, {"deadlineBoottimeNs": "2000000001"},
                {"expiresAtUnixNanos": 9000000001}, {"approvedPeer": 123}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                listener.approval(canonical(value | fields), request_raw=raw, input_sha256=sha(b"input"))
        self.assertEqual(listener.INPUT_PATH, "/etc/catchplate/native-genesis-authority/listener-execution.input.json")
        self.assertEqual(listener.APPROVAL_PATH, "/etc/catchplate/native-genesis-authority/listener-execution.approval.json")

    def test_raw_configuration_is_closed_canonical_and_bounded(self):
        value, clocks = fixture()
        for raw in (canonical(value) + b"\n", b" " * 4097, canonical(value | {"endpoint": "/tmp/replacement"}),
                canonical(value | {"apiVersion": execution.HANDOFF_CONFIGURATION_API})):
            with self.assertRaises(ValueError): listener.configuration(raw, **clocks)
        with self.assertRaises(ValueError): listener.CoreHandoffListener(object())


if __name__ == "__main__":
    unittest.main()
