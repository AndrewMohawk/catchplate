#!/usr/bin/env python3
"""Pure selected installer/CLI controls, not a publication or live rendezvous.

The fixture is synthetic public metadata. No protected destination, process
owner, key, peer custody, independent decision or successful cleanup is faked.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import install_native_pilot_genesis_rendezvous as command
from scripts import native_pilot_authority_runtime_entrypoint as entry
from scripts.test_native_pilot_genesis_rendezvous import fixture
from serverware import native_pilot_genesis_authority as authority
from serverware import native_pilot_genesis_handoff_listener as legacy
from serverware import native_pilot_genesis_jobs as jobs
from serverware import native_pilot_genesis_rendezvous_install as installation
from serverware import native_pilot_genesis_rendezvous_profile as profile

p = profile.p


def prepare(value, **changes):
    parameters = dict(request_sha256=p.sha(value["request_raw"]), input_sha256=p.sha(value["input_raw"]),
        approval_sha256=p.sha(value["approval_raw"]),
        **{name: value[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")})
    parameters.update(changes)
    return installation.prepare_input(value["request_raw"], value["input_raw"], value["approval_raw"], **parameters)


def authority_arguments():
    value = ["--run-native-genesis-rendezvous", "--supervisor-inventory-fd", "3",
        "--supervisor-inventory-sha256", p.sha(b"synthetic inventory"),
        "--genesis-listener-configuration-fd", "4",
        "--genesis-listener-configuration-sha256", p.sha(b"synthetic rendezvous configuration")]
    for purpose in jobs.KEY_PURPOSES:
        value.extend(("--authority-key", purpose + "=5"))
    return value


def installer_arguments():
    value, result = fixture(), []
    for fd, name in enumerate(("request", "input", "approval"), 3):
        result.extend(("--" + name + "-fd", str(fd), "--" + name + "-sha256", p.sha(value[name + "_raw"])))
    return result


class RendezvousInstallationControls(unittest.TestCase):
    def test_complete_public_pair_returns_only_bound_reply(self):
        value = fixture()
        prepared = prepare(value)
        self.assertEqual(prepared["deadline"], 2_000_000_000)
        self.assertEqual(prepared["epochLimit"], 9_000_000_000)
        self.assertEqual(profile.reply(p.canonical(prepared["reply"]), value["request_raw"]), prepared["reply"])
        self.assertEqual(set(prepared["reply"]), set(profile.REPLY_FIELDS))
        self.assertNotIn("approved", prepared["reply"])
        self.assertNotIn("installed", prepared["reply"])

    def test_all_three_independent_pins_are_required(self):
        value = fixture()
        for key in ("request_sha256", "input_sha256", "approval_sha256"):
            with self.subTest(pin=key), self.assertRaises(ValueError):
                prepare(value, **{key: p.sha(b"unrelated original")})

    def test_no_approval_is_derived_from_valid_execution(self):
        value = fixture()
        for raw in (b"{}", value["input_raw"], value["approval_raw"] + b"\n"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                prepare(value | {"approval_raw": raw})
        approval = p.document(value["approval_raw"], 4096)
        approval["apiVersion"] = legacy.APPROVAL_API
        with self.assertRaises(ValueError): prepare(value | {"approval_raw": p.canonical(approval)})

    def test_current_boot_and_both_original_clock_ceilings(self):
        value = fixture()
        for changed in ({"now_boottime_ns": 2_000_000_000}, {"now_unix_ns": 9_000_000_000},
                {"boot": (value["boot"][0], 12, 11)}, {"now_boottime_ns": 999_999_999}):
            with self.subTest(changed=changed), self.assertRaises(ValueError): prepare(value, **changed)

    def test_execution_cannot_replace_actual_observed_receiver(self):
        value = fixture()
        selected = p.document(value["input_raw"], 4096)
        selected["coreHandoff"]["peerPid"] = 201
        changed_raw = p.canonical(selected)
        approval = p.document(value["approval_raw"], 4096)
        approval["inputSha256"] = p.sha(changed_raw)
        with self.assertRaises(ValueError):
            prepare(value | {"input_raw": changed_raw, "approval_raw": p.canonical(approval)})

    def test_rendezvous_mode_is_explicit_and_preserves_catalogues(self):
        values = authority_arguments()
        selected = authority.arguments(values)
        self.assertTrue(selected["rendezvous"])
        self.assertTrue(selected["listener"])
        self.assertTrue(selected["handoff"])
        self.assertNotIn("core_handoff_fd", selected)
        self.assertTrue(entry.valid_arguments(values))
        old = authority.arguments(["--run-native-genesis-listener", *values[1:]])
        self.assertFalse(old["rendezvous"])
        self.assertEqual((len(jobs.JOBS), len(jobs.HANDOFF_JOBS), len(jobs.KEY_PURPOSES)), (64, 66, 36))

    def test_rendezvous_rejects_wrong_flag_family_and_missing_key(self):
        values = authority_arguments()
        for changed in (values[:5] + ["--genesis-configuration-fd", *values[6:]],
                values[:9] + ["--core-handoff-fd", "6"] + values[9:], values[:-2],
                ["--run-native-genesis", *values[1:]]):
            with self.subTest(arguments=changed), self.assertRaises(ValueError): authority.arguments(changed)
        self.assertFalse(entry.valid_arguments(values[:5] + ["--genesis-configuration-fd", *values[6:]]))

    def test_installer_requires_three_distinct_fd_hash_pairs(self):
        values = installer_arguments()
        parsed = command.arguments(values)
        self.assertEqual((parsed["request_fd"], parsed["input_fd"], parsed["approval_fd"]), (3, 4, 5))
        for changed in (values[:-2], values + values[:2], values[:5] + ["3"] + values[6:],
                values[:1] + ["03"] + values[2:], values[:3] + ["unknown"] + values[4:]):
            with self.subTest(arguments=changed), self.assertRaises(ValueError): command.arguments(changed)

    def test_fixed_paths_cannot_be_added_to_public_approval(self):
        value = fixture()
        approval = p.document(value["approval_raw"], 4096) | {"path": "/tmp/replacement"}
        with self.assertRaises(ValueError): prepare(value | {"approval_raw": p.canonical(approval)})
        self.assertEqual(installation._PATHS, (legacy.INPUT_PATH, legacy.APPROVAL_PATH))
        self.assertEqual((installation.MAX_REQUEST, installation.MAX_INPUT, installation.MAX_APPROVAL), (32768, 4096, 4096))

    def test_public_data_cannot_construct_retained_installer(self):
        with self.assertRaises(ValueError): installation.GenesisRendezvousInstallation(object())
        value = fixture()
        for raw in (b" " * (installation.MAX_REQUEST + 1), value["request_raw"] + b"\n", value["sender_raw"]):
            with self.subTest(raw=raw), self.assertRaises(ValueError): prepare(value | {"request_raw": raw})


if __name__ == "__main__":
    unittest.main()
