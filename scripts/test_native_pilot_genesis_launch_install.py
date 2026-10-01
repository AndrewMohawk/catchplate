#!/usr/bin/env python3
"""Authenticated public installation plans only; no protected writes or owners.

Real synthetic signatures cover relocated fixed C9 runtime/ciphertext pins and
the complete endpoint→grant→ordinary→coordinator order. No filesystem success,
KMS decryption, runtime owner or installer admission is mocked into existence.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_encrypted_authority as encrypted
from serverware import native_pilot_genesis_verifier_authority as verifier
from serverware import native_pilot_genesis_launch_install as install
from serverware import native_pilot_genesis_launch_profile as launch
import test_native_pilot_genesis_launch as launches
import test_native_pilot_genesis_transport_authority as transport
import test_native_pilot_genesis_key_authority as key_tests

p = g.p


def _row(base, role, *, runtime_raw=None):
    row = transport.attach_ciphertext(base, role, runtime_raw=runtime_raw)
    payload = g.document(row["delivery"]["raw"], 65536)["payload"]
    payload["runtimeConfig"]["path"] = install.DESTINATIONS[role]["runtime"]
    payload["credentials"][0]["original"]["path"] = install.DESTINATIONS[role]["encryptedInventory"]
    delivery = transport.replace_c9(row["delivery"], payload)
    pair = transport.rebind_pair(base, role, delivery)
    row.update(delivery=delivery, pair=pair)
    for name, module, api, domain in (("encrypted", encrypted, encrypted.OUTPUT_API, transport.ENCRYPTED_DOMAIN),
            ("verifier", verifier, verifier.OUTPUT_API, transport.VERIFIER_DOMAIN)):
        value = module.input_document(row[name + "_input_raw"])
        value.update({field: raw.decode("ascii") for field, raw in pair.items()})
        raw = p.canonical(value)
        checked = module.prepare_input(role, raw, **transport.clocks_for(base))
        row[name + "_input_raw"] = raw
        row[name + "_raw"] = transport.independent_signed(api, domain, checked["payload"], base["supervisor_key"])
    return row


def _fixed_input(base, role, row, contexts, clocks):
    value, _ = launches._input(base, role, row, contexts, clocks)
    for name, pin in value["pins"].items():
        if name not in install.PREREQUISITES: pin["path"] = install.DESTINATIONS[role][name]
    api, operation = launch.SELECTORS[role]
    selected = {"apiVersion": api, "keyAdmission": {"apiVersion": "serverware.nativeShadowGuestLaunch/v1",
        **{name: value["pins"][name] for name in launch.INNER}}}
    if operation: selected[operation] = value["pins"]["serviceGrant"]
    value["pins"]["launch"]["sha256"] = p.sha(g.canonical(selected))
    return value


def envelope(role, value, clocks):
    raw = p.canonical(value)
    bundle = launch.prepare_input(role, raw, **clocks)["bundleOriginal"]
    return p.canonical({"apiVersion": install.API, "role": role,
        "launchInputOriginal": raw.decode("ascii"), "bundleOriginal": bundle.decode("ascii")})


def fixture():
    base = key_tests.fixture(); clocks = transport.clocks_for(base)
    rows = {role: _row(base, role) for role in install.ROLES[:-1]}
    contexts = launches._native_grants(base, rows, clocks)
    runtime = launches._coordinator_runtime(base, rows, contexts, clocks)
    rows[install.ROLES[-1]] = _row(base, install.ROLES[-1], runtime_raw=runtime)
    inputs = {role: _fixed_input(base, role, row, contexts, clocks) for role, row in rows.items()}
    raw = {role: envelope(role, value, clocks) for role, value in inputs.items()}
    return dict(base=base, clocks=clocks, rows=rows, inputs=inputs, raw=raw)


class GenesisLaunchInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.f = fixture()

    def prepare(self, role=None, raw=None, **clocks):
        role = role or install.ROLES[0]
        return install.prepare_input(role, self.f["raw"][role] if raw is None else raw, **(clocks or self.f["clocks"]))

    def refused(self, role=None, raw=None, **clocks):
        with self.assertRaises((ValueError, InvalidSignature, KeyError, TypeError)):
            self.prepare(role, raw, **clocks)

    def test_all_three_complete_authenticated_plans_are_components_before_launch(self):
        for role in install.ROLES:
            plan = self.prepare(role)
            names = tuple(row["name"] for row in plan["rows"])
            self.assertEqual(names, (*install.COMPONENTS, *(("serviceGrant",) if role != install.ROLES[-1] else ()), "launch"))
            self.assertEqual(tuple(row["name"] for row in plan["prerequisites"]), install.PREREQUISITES)
            self.assertEqual(plan["result"]["launchPin"], plan["rows"][-1]["pin"])
            for row in plan["rows"]:
                self.assertEqual(row["pin"]["path"], install.DESTINATIONS[role][row["name"]])
                self.assertEqual(row["pin"]["sha256"], p.sha(row["raw"]))
                self.assertNotEqual(row["pin"]["path"], "/etc/serverware/native-shadow-guest-launch.json")
            self.assertEqual(install.checked_result(role, self.f["raw"][role], plan["result"], **self.f["clocks"]), plan["result"])

    def test_runtime_is_root_owned_and_only_encrypted_credential_is_role_owned(self):
        for role in install.ROLES:
            plan = self.prepare(role)
            guest = self.f["rows"][role]["delivery"]["configuration"]
            for row in plan["rows"]:
                expected = (guest["uid"], guest["gid"]) if row["name"] == "encryptedInventory" else (0, 0)
                self.assertEqual((row["uid"], row["gid"]), expected)
            self.assertFalse(any(row["name"].startswith("shadow-key-") for row in plan["rows"]))

    def test_valid_bundle_with_a_different_approved_host_launch_destination_is_refused(self):
        role = install.ROLES[0]
        value = copy.deepcopy(self.f["inputs"][role])
        value["pins"]["launch"]["path"] = "/etc/serverware/native-shadow-guest-launch.json"
        # This remains an authentic pure launch bundle but is not this fixed
        # installer's destination; no success validator is monkeypatched.
        self.refused(role, envelope(role, value, self.f["clocks"]))

    def test_bundle_or_prior_input_splice_is_not_an_installation_plan(self):
        role = install.ROLES[0]
        value = install.input_document(self.f["raw"][role])
        other = install.input_document(self.f["raw"][install.ROLES[1]])
        value["bundleOriginal"] = other["bundleOriginal"]
        self.refused(role, p.canonical(value))
        value = install.input_document(self.f["raw"][role])
        prior = p.document(value["launchInputOriginal"].encode("ascii"), launch.MAX_INPUT)
        prior["authorizations"]["closure"]["authorizationOriginal"] = prior["authorizations"]["verifier-transport"]["authorizationOriginal"]
        value["launchInputOriginal"] = p.canonical(prior).decode("ascii")
        self.refused(role, p.canonical(value))

    def test_original_boot_and_both_clock_ceilings_are_preserved(self):
        role = install.ROLES[0]; plan = self.prepare(role)
        for replacement in ({"now_boottime_ns": plan["deadline"]}, {"now_unix_ns": plan["epochLimit"]}, {"boot": p.encoded(bytes(16))}):
            self.refused(role, **{**self.f["clocks"], **replacement})

    def test_unknown_fields_roles_and_claimed_install_result_drift_refuse(self):
        role = install.ROLES[0]
        value = install.input_document(self.f["raw"][role]); value["overwrite"] = True
        self.refused(role, p.canonical(value))
        value = install.input_document(self.f["raw"][role]); value["role"] = "bridge"
        self.refused(role, p.canonical(value))
        plan = self.prepare(role); result = copy.deepcopy(plan["result"])
        result["pins"]["runtime"]["sha256"] = p.sha(b"not the authenticated runtime")
        with self.assertRaises(ValueError):
            install.checked_result(role, self.f["raw"][role], result, **self.f["clocks"])


if __name__ == "__main__": unittest.main()
