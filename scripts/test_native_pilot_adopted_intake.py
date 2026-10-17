#!/usr/bin/env python3
"""Pure fixed intake-selection controls plus one actual own-process read.

No protected inputs, connection, ReceivedGenesisCore, native adoption, owner
cleanup, signer or pilot is fabricated. A valid configuration below means only
closed public grammar and original bounds; it is not an approved live ceremony.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import native_pilot_adopted_intake as intake


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def fixture():
    boot = (base64.urlsafe_b64encode(bytes(range(16))).rstrip(b"=").decode("ascii"), 11, 12)
    value = {"apiVersion": "catchplate.nativePilotAdoptedIntakeConfiguration/v1",
        "purpose": "receive-cold-core-for-adopted-native-pilot", "sender": {"pid": 1234, "uid": 0, "gid": 0, "startTimeTicks": 456},
        "bootIdBase64url": boot[0], "timeNamespaceDevice": boot[1], "timeNamespaceInode": boot[2],
        "issuedAtBoottimeNs": "100", "startupDeadlineBoottimeNs": "200", "lifetimeDeadlineBoottimeNs": "300",
        "issuedAtUnixNanos": 1000, "expiresAtUnixNanos": 1200}
    return value, dict(boot=boot, now_boottime_ns=150, now_unix_ns=1050)


class AdoptedIntakeControls(unittest.TestCase):
    def test_exact_original_configuration_and_fixed_endpoint(self):
        value, clocks = fixture()
        self.assertEqual(intake.validate_configuration(canonical(value), **clocks), value)
        self.assertEqual(intake.ENDPOINT, "/run/catchplate/native-pilot-core-handoff/core.sock")
        self.assertEqual(intake.DIRECTORY, "/run/catchplate/native-pilot-core-handoff")
        result = intake.validate_configuration(canonical(value), **clocks)
        result["sender"]["pid"] = 999
        self.assertEqual(value["sender"]["pid"], 1234)

    def test_fixed_argv_is_explicit_and_legacy_stays_closed(self):
        digest = "sha256:" + hashlib.sha256(b"synthetic approved input pin").hexdigest()
        arguments = ["--run-adopted-native-pilot", "--intake-configuration-fd", "17", "--intake-configuration-sha256", digest]
        self.assertEqual(intake.conductor_arguments(configuration_fd=17, configuration_sha256=digest), arguments)
        self.assertEqual(intake.invocation(arguments), dict(configuration_fd=17, configuration_sha256=digest))
        self.assertIsNone(intake.invocation(["--run-native-pilot"]))
        for changed in ([], arguments + ["--run-native-pilot"], arguments[:-1],
                ["--run-native-pilot", *arguments[1:]], [arguments[0], "--core-fd", *arguments[2:]],
                [*arguments[:2], "017", *arguments[3:]], [*arguments[:2], "2", *arguments[3:]],
                [*arguments[:2], "+17", *arguments[3:]], [*arguments[:2], "17\n", *arguments[3:]]):
            with self.subTest(arguments=changed), self.assertRaises(ValueError):
                intake.invocation(changed)
        with self.assertRaises(ValueError):
            intake.conductor_arguments(configuration_fd=True, configuration_sha256=digest)

    def test_original_boottime_and_unix_limits_do_not_renew(self):
        value, clocks = fixture()
        for fields in ({"now_boottime_ns": 99}, {"now_boottime_ns": 300},
                {"now_unix_ns": 999}, {"now_unix_ns": 1200}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                intake.validate_configuration(canonical(value), **(clocks | fields))
        # Retained configuration is lifetime-valid; actual open/connect/ACK
        # additionally apply its unchanged startup deadline.
        later = intake.validate_configuration(canonical(value), **(clocks | {"now_boottime_ns": 250}))
        self.assertEqual(later["startupDeadlineBoottimeNs"], "200")
        for fields in ({"issuedAtBoottimeNs": "200"}, {"startupDeadlineBoottimeNs": "300"},
                {"expiresAtUnixNanos": 1000}, {"issuedAtUnixNanos": 1100}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                intake.validate_configuration(canonical(value | fields), **clocks)

    def test_exact_boot_and_time_namespace_are_required(self):
        value, clocks = fixture()
        for name, changed in (("bootIdBase64url", base64.urlsafe_b64encode(b"x" * 16).rstrip(b"=").decode("ascii")),
                ("timeNamespaceDevice", 13), ("timeNamespaceInode", 14)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                intake.validate_configuration(canonical(value | {name: changed}), **clocks)

    def test_sender_is_exact_root_process_policy_not_numeric_fd(self):
        value, clocks = fixture()
        for fields in ({"pid": True}, {"pid": 1}, {"uid": 1000}, {"gid": 1000},
                {"uid": False}, {"startTimeTicks": 0}, {"pidfd": 17}):
            changed = copy.deepcopy(value); changed["sender"].update(fields)
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                intake.validate_configuration(canonical(changed), **clocks)

    def test_closed_grammar_canonical_bytes_and_size(self):
        value, clocks = fixture()
        for fields in ({"apiVersion": "catchplate.nativePilotAdoptedIntakeConfiguration/v2"},
                {"purpose": "approve-adoption"}, {"endpoint": "/tmp/caller.sock"}, {"receivedCore": {"fd": 17}},
                {"expiresAtUnixNanos": 1 << 63}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                intake.validate_configuration(canonical(value | fields), **clocks)
        for raw in (canonical(value) + b"\n", b" " * (intake.MAX_CONFIGURATION + 1),
                canonical(value).replace(b'"pid":1234', b'"pid":1234,"pid":1234')):
            with self.assertRaises(ValueError): intake.validate_configuration(raw, **clocks)

    def test_public_dtos_do_not_construct_actual_intake_owners(self):
        for owner in (intake.IntakeConfiguration, intake.AdoptedIntake):
            with self.subTest(owner=owner.__name__), self.assertRaises(ValueError):
                owner(object())

    def test_sender_start_parser_matches_actual_own_process_only(self):
        # Real read-only process fact, not a PIDFD/core/adoption acceptance.
        self.assertEqual(intake._sender_start(os.getpid()), intake.originals._start())


if __name__ == "__main__":
    unittest.main()
