#!/usr/bin/env python3
"""Pure selected-owner intake controls; no protected resource owner is faked.

Synthetic in-memory C9 and target-history signatures exercise exact receiver
logic. These controls do not allocate journals, fork services, install files,
produce native acceptance or claim real publication/grant ownership.
"""
import copy
import json
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))
from catchplate import custody_generation_grants as g
from catchplate import custody_generation_initial_state as state
from catchplate import custody_spool_inputs as spool
from catchplate import native_pilot_ordinary_initial_profile as initial
from test_native_pilot_ordinary_generations import context
from test_native_pilot_adopted_services import target_fixture
from test_native_pilot_ordinary_keys import canonical, encoded, sha


def delivery_fixture(role):
    f = context()
    payload = json.loads(f["deliveries"][role])["payload"]
    for name, mode in (("publication-journal", stat.S_IFDIR | 0o700), ("publication-grant", stat.S_IFREG | 0o600)):
        payload["activation"].append({"name": name, "fd": 6 + len(payload["activation"]), "device": 8,
            "inode": 999000 + len(payload["activation"]), "mode": mode,
            "uid": f["cold"][role]["uid"], "gid": f["cold"][role]["gid"]})
    return f, payload


def signed(f, role, payload):
    return g.canonical({"apiVersion": "catchplate.policyCustodyGuestDelivery/v1", "payload": payload,
        "signatureBase64url": encoded(f["delivery_keys"][role].sign(g.c9.DOMAIN + g.canonical(payload)))})


def admit(f, role, payload, raw, **changes):
    values = dict(signed_raw=raw, cold_raw=canonical(f["cold"][role]), cold_sha=sha(canonical(f["cold"][role])),
        role=role, activation=payload["activation"],
        boot=tuple(payload[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")),
        startup=int(payload["startupDeadlineBoottimeNs"]), lifetime=int(payload["lifetimeDeadlineBoottimeNs"]),
        now=1300, commitment=role in (g.ROLES[0], g.ROLES[3]), spool=True, effects=True, adoption=True)
    return g._admit_delivery(**(values | changes))


class AdoptedInputControls(unittest.TestCase):
    def test_exact_signed_drs_csa_additions(self):
        for role in (g.ROLES[0], g.ROLES[3]):
            f, payload = delivery_fixture(role); raw = signed(f, role, payload)
            checked, guest = admit(f, role, payload, raw)
            self.assertEqual(checked, raw)
            self.assertEqual(guest["deliverySha256"], sha(raw))
            self.assertEqual([row["name"] for row in payload["activation"]][-2:], ["publication-journal", "publication-grant"])

    def test_old_flags_and_other_role_cannot_acquire_publication(self):
        f, payload = delivery_fixture(g.ROLES[0]); raw = signed(f, g.ROLES[0], payload)
        with self.assertRaises(ValueError): admit(f, g.ROLES[0], payload, raw, adoption=False)
        f, payload = delivery_fixture(g.ROLES[1]); raw = signed(f, g.ROLES[1], payload)
        with self.assertRaises(ValueError): admit(f, g.ROLES[1], payload, raw)

    def test_unsigned_change_and_descriptor_drift_refuse(self):
        role = g.ROLES[0]; f, payload = delivery_fixture(role); raw = signed(f, role, payload)
        value = json.loads(raw); value["signatureBase64url"] = encoded(bytes(64))
        with self.assertRaises(InvalidSignature): admit(f, role, payload, canonical(value))
        wrong = copy.deepcopy(payload); wrong["activation"][-1]["fd"] += 1
        with self.assertRaises(ValueError): admit(f, role, wrong, signed(f, role, wrong))
        wrong = copy.deepcopy(payload); wrong["activation"][-1]["name"] = "another-grant"
        with self.assertRaises(ValueError): admit(f, role, wrong, signed(f, role, wrong))

    def test_credential_alias_and_unrepresentable_signed_integer_refuse(self):
        role = g.ROLES[0]; f, payload = delivery_fixture(role)
        wrong = copy.deepcopy(payload); wrong["credentials"][0]["name"] = "publication-grant"
        with self.assertRaises(ValueError): admit(f, role, wrong, signed(f, role, wrong))
        wrong = copy.deepcopy(payload); wrong["activation"][-1]["inode"] = 1 << 63
        with self.assertRaises(ValueError): admit(f, role, wrong, signed(f, role, wrong))

    def test_exact_directory_inventory_preserves_other_three(self):
        self.assertEqual(sum(map(len, state.DIRECTORIES.values())), 15)
        self.assertEqual(sum(map(len, state.ADOPTED_DIRECTORIES.values())), 17)
        for role in g.ROLES:
            extra = ("publication-journal",) if role in (g.ROLES[0], g.ROLES[3]) else ()
            self.assertEqual(state.directories(True)[role], state.DIRECTORIES[role] + extra)
        self.assertNotEqual(state.API, state.ADOPTED_API)

    def test_adopted_spool_refuses_legacy_native_without_history(self):
        for name, (_, api) in spool.EFFECT_NATIVE.items():
            if name == "retrieval":
                continue
            raw = canonical({"payload": {"apiVersion": api}, "signature": encoded(bytes(64))})
            with self.assertRaises(ValueError):
                spool._native_original(name, raw, expected_api=api, effects=True,
                    proof_scope_original="{}", adoption=True)

    def test_actual_runtime_history_receiver_selects_v3_only(self):
        f = target_fixture(); record = f["wrapper"]["initialState"]
        guest = {name: record[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
            "invocationId", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")}
        row = next(iter(record["directories"].values()))["identity"]
        guest.update(serviceRole=g.ROLES[0], uid=row["uid"], gid=row["gid"], issuedAtBoottimeNs="1200")
        self.assertEqual(initial.runtime_manifest(canonical(f["wrapper"]), runtime=f["header"], guest=guest), f["wrapper"]["history"])
        old = dict(f["header"], apiVersion="catchplate.policyCustodyServiceRuntimeConfig/v8")
        with self.assertRaises(ValueError): initial.runtime_manifest(canonical(f["wrapper"]), runtime=old, guest=guest)


if __name__ == "__main__":
    unittest.main()
