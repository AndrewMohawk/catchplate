#!/usr/bin/env python3
"""Cold closure public-data controls; no image admission or real signer owner.

Actual-format deterministic signatures use explicitly synthetic observations
and image pins. These controls do not claim C9/kernel ownership, a loaded image,
native closure acceptance, key provisioning or independent policy approval.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_closure_set as sets
from catchplate import native_pilot_genesis_closure_authority as authority
from catchplate import native_pilot_genesis_key_profile as keys
import test_native_pilot_genesis_key_authority as fixtures

p = g.p
DOMAIN = "catchplate.nativeCustodyClosureAssignment.signature/v6"


def input_for(fixture, role):
    original = p.document(fixture["pairs"][role]["roleKeyInputOriginal"], keys.MAX_INPUT)
    return {"apiVersion": authority.API, "role": role,
        **{name: original[name] for name in keys.SOURCE_FIELDS},
        "policy": {name: original["policy"][name] for name in ("issuedAtUnixNanos", "expiresAtUnixNanos")}}


def independently_signed(prepared, key, *, domain=DOMAIN):
    result = copy.deepcopy(prepared["result"])
    signed = fixtures.independent_signed(domain, result["authorization"]["payload"], key)
    result["authorization"] = g.document(signed, keys.MAX_OUTPUT)
    return g.canonical(result)


class GenesisClosureAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = fixtures.fixture()
        cls.clocks = {name: cls.f[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")}

    def prepare(self, value, **clocks):
        return authority.prepare_input(value["role"], p.canonical(value), **(clocks or self.clocks))

    def check(self, value, raw):
        return authority.checked_result(value["role"], p.canonical(value),
            {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **self.clocks)

    def test_all_three_members_emit_exact_v6_and_native_signature_framing(self):
        for role in authority.ROLES:
            with self.subTest(role=role):
                value = input_for(self.f, role); prepared = self.prepare(value)
                raw = independently_signed(prepared, self.f["supervisor_key"])
                self.assertEqual(self.check(value, raw), raw)
                result = g.document(raw, authority.MAX_OUTPUT)
                payload = result["authorization"]["payload"]
                self.assertEqual(result["apiVersion"], "catchplate.nativeCustodyClosure/v6")
                self.assertEqual(payload["apiVersion"], "catchplate.nativeCustodyClosureAssignment/v6")
                self.assertEqual(payload["profile"], "native-publication-genesis-closure-set-v2")
                self.assertEqual(payload["guestRole"], role)
                self.assertEqual(payload["manifestSha256"], result["manifest"]["manifestSha256"])
                leaf = sets.leaf_binding(result["closureSet"], role, api_version=sets.GENESIS_BOOTSTRAP_API)
                for name in ("setRootSha256", "seccompSetRootSha256", "leafSha256"):
                    self.assertEqual(payload[name], leaf[name])
                self.assertEqual(payload["guest"]["deliverySha256"], p.sha(self.f["deliveries"][role]["raw"]))

    def test_only_coordinator_manifest_has_measured_bootstrap_late_runtime_split(self):
        for role in authority.ROLES:
            prepared = self.prepare(input_for(self.f, role))
            manifest, guest = prepared["manifest"], prepared["guest"]
            self.assertEqual(manifest["imageSha256"], self.f["deliveries"][role]["image_sha256"])
            self.assertEqual(manifest["workerExecutableSha256"], self.f["deliveries"][role]["executable_sha256"])
            self.assertEqual(guest["runtimeConfigurationSha256"], p.sha(self.f["deliveries"][role]["runtime_raw"]))
            if role == authority.ROLES[-1]:
                self.assertEqual(manifest["apiVersion"], "catchplate.nativeCustodyExecutionClosure/v2")
                self.assertEqual(manifest["profile"], "measured-bootstrap-late-runtime-static-amd64-v1")
                self.assertEqual(manifest["runtimeConfigurationSha256"], p.sha(g.canonical(keys.BOOTSTRAP)))
                self.assertNotEqual(manifest["runtimeConfigurationSha256"], guest["runtimeConfigurationSha256"])
            else:
                self.assertEqual(manifest["apiVersion"], "catchplate.nativeCustodyExecutionClosure/v1")
                self.assertEqual(manifest["profile"], "sealed-memfd-squashfs-static-amd64-v1")
                self.assertEqual(manifest["runtimeConfigurationSha256"], guest["runtimeConfigurationSha256"])

    def test_old_outer_assignment_profile_and_signature_domain_refuse(self):
        value = input_for(self.f, authority.ROLES[-1]); prepared = self.prepare(value)
        raw = independently_signed(prepared, self.f["supervisor_key"],
            domain="catchplate.nativeCustodyClosureAssignment.signature/v4")
        with self.assertRaises(InvalidSignature):
            self.check(value, raw)
        for target, field, replacement in (("outer", "apiVersion", "catchplate.nativeCustodyClosure/v4"),
                ("payload", "apiVersion", "catchplate.nativeCustodyClosureAssignment/v4"),
                ("payload", "profile", "native-publication-genesis-closure-set-v1")):
            changed = copy.deepcopy(prepared)
            row = changed["result"] if target == "outer" else changed["result"]["authorization"]["payload"]
            row[field] = replacement
            raw = independently_signed(changed, self.f["supervisor_key"])
            with self.assertRaises(ValueError):
                self.check(value, raw)

    def test_same_signer_cannot_substitute_guest_role_manifest_or_complete_set(self):
        value = input_for(self.f, authority.ROLES[0]); prepared = self.prepare(value)
        changes = (
            lambda result: result["authorization"]["payload"]["guest"].update(deliverySha256=fixtures.labelled("other delivery")),
            lambda result: result["authorization"]["payload"].update(guestRole=authority.ROLES[1]),
            lambda result: result["manifest"].update(imageSha256=fixtures.labelled("other image")),
            lambda result: result["closureSet"]["members"].reverse(),
            lambda result: result["authorization"]["payload"].update(leafSha256=fixtures.labelled("other leaf")),
        )
        for mutate in changes:
            changed = copy.deepcopy(prepared); mutate(changed["result"])
            with self.assertRaises(ValueError):
                self.check(value, independently_signed(changed, self.f["supervisor_key"]))

    def test_expired_original_window_wrong_boot_and_false_result_pin_refuse(self):
        value = input_for(self.f, authority.ROLES[0]); prepared = self.prepare(value)
        for clocks in ({**self.clocks, "now_boottime_ns": prepared["deadline"]},
                {**self.clocks, "now_unix_ns": prepared["epochLimit"]},
                {**self.clocks, "boot": (p.encoded(bytes([77]) * 16), *self.clocks["boot"][1:])}):
            with self.assertRaises(ValueError):
                self.prepare(value, **clocks)
        raw = independently_signed(prepared, self.f["supervisor_key"])
        with self.assertRaises(ValueError):
            authority.checked_result(value["role"], p.canonical(value),
                {"original": raw.decode("ascii"), "sha256": fixtures.labelled("wrong pin")}, **self.clocks)

    def test_closed_source_selector_no_hot_fallback_or_future_authority_fields(self):
        value = input_for(self.f, authority.ROLES[0])
        for changes in ({"apiVersion": "catchplate.nativePilotClosureAuthorityInput/v2"}, {"role": "bridge"},
                {"futureGrantSha256": fixtures.labelled("future grant")},
                {"deliveryOriginal": self.f["deliveries"][authority.ROLES[1]]["raw"].decode("ascii")}):
            with self.assertRaises((ValueError, InvalidSignature)):
                self.prepare({**value, **changes})


if __name__ == "__main__":
    unittest.main()
