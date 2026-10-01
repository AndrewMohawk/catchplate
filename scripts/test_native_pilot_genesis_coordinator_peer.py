#!/usr/bin/env python3
"""Synthetic peer-data controls; no process owner or kernel capture runs."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import test_native_pilot_genesis_parent_authority as fixtures
from serverware import custody_generation_grants as codec
from serverware import native_pilot_bridge_preparation as binding
from serverware import native_pilot_genesis_coordinator_peer as peer

p = codec.p


def fixture():
    f = fixtures.fixture()
    observation = codec.document(f["observation_raw"], 32768)
    window = codec.document(f["precreation_raw"], 32768)["payload"]
    value = {"apiVersion": peer.API, "profile": peer.wire.PROFILE, "ownerKind": peer.ROLE,
        "phase": "parked-pre-exec", "configurationSha256": p.sha(f["configuration_raw"]),
        "sourceOriginalSha256": p.sha(f["observation_raw"]),
        **{field: window[field] for field in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
            "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")},
        "observedAtBoottimeNs": "1500000000", "peers": {peer.ROLE: {
            "processId": observation["processId"], "startTimeTicks": observation["startTimeTicks"],
            "pidfd": {"device": observation["pidfdDevice"], "inode": observation["pidfdInode"]},
            "targetExecutable": observation["executable"],
            "cgroup": {"pathSha256": p.sha(b"/synthetic/cold"), "mountId": 4, "inode": 5}}}}
    row = value["peers"][peer.ROLE]
    approved = {"uid": 64001, "gid": 64001, "pid": row["processId"], "startTimeTicks": row["startTimeTicks"],
        **{target: row["targetExecutable"][source] for target, source in (
            ("executableDevice", "device"), ("executableInode", "inode"),
            ("executableLength", "length"), ("executableSha256", "sha256"))},
        **{target: row["cgroup"][source] for target, source in (
            ("cgroupPathSha256", "pathSha256"), ("cgroupMountId", "mountId"), ("cgroupInode", "inode"))},
        "securityLabelSha256": p.sha(b"approved-label"), "configurationGenerationSha256": p.sha(b"approved-generation")}
    approved["processIdentitySha256"] = binding.peer_identity(approved)
    kw = {name: f[name] for name in ("observation_raw", "configuration_raw", "precreation_raw", "boot")}
    kw.update(delivery_configuration_raw=f["cold_raw"], now_boottime_ns=f["now"])
    return value, approved, kw


class Controls(unittest.TestCase):
    def setUp(self):
        self.value, self.approved, self.kw = fixture()

    def check(self, value=None, approved=None, **kw):
        return peer.expected_peer(codec.canonical(self.value if value is None else value),
            approved=self.approved if approved is None else approved, **(self.kw | kw))

    def test_exact_observation_and_independent_approval(self):
        self.assertEqual(self.check(), self.approved)
        result = self.check()
        result["uid"] = 1
        self.assertEqual(self.check()["uid"], 64001)

    def test_legacy_and_wrong_role_are_not_cold(self):
        for extra in ({"apiVersion": peer.wire.API}, {"ownerKind": "native-endpoints"},
                      {"phase": "executing-gate"}, {"ready": True}):
            with self.assertRaises(ValueError):
                self.check(self.value | extra)
        with self.assertRaises(ValueError):
            peer.wire.shape(codec.canonical(self.value))

    def test_clock_and_original_window_cannot_be_renewed(self):
        for now in (1_000_000_000, 5_000_000_000, 10_000_000_000):
            with self.assertRaises(ValueError):
                self.check(now_boottime_ns=now)
        for field in ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"):
            with self.assertRaises(ValueError):
                self.check(self.value | {field: str(int(self.value[field]) + 1)})
        with self.assertRaises(ValueError):
            self.check(boot=(p.encoded(bytes([8]) * 16), 7, 8))

    def test_observation_pid_pidfd_and_target_are_exact(self):
        for path in (("processId",), ("startTimeTicks",), ("pidfd", "inode"), ("targetExecutable", "inode")):
            value = copy.deepcopy(self.value)
            row = value["peers"][peer.ROLE]
            for field in path[:-1]:
                row = row[field]
            row[path[-1]] += 1
            with self.assertRaises(ValueError):
                self.check(value)

    def test_cgroup_is_not_filled_from_approved_peer(self):
        value = copy.deepcopy(self.value)
        value["peers"][peer.ROLE]["cgroup"]["inode"] += 1
        with self.assertRaises(ValueError):
            self.check(value)
        with self.assertRaises(ValueError):
            self.check(self.value | {"sourceOriginalSha256": p.sha(b"different-observation")})

    def test_root_ids_and_unbound_labels_rejected(self):
        for field, replacement in (("uid", 0), ("gid", 0), ("securityLabelSha256", p.sha(b"other-label")),
                                   ("configurationGenerationSha256", p.sha(b"other-generation"))):
            approved = self.approved | {field: replacement}
            with self.assertRaises(ValueError):
                self.check(approved=approved)
        approved = self.approved | {"uid": 64002}
        approved["processIdentitySha256"] = binding.peer_identity(
            {key: value for key, value in approved.items() if key != "processIdentitySha256"})
        with self.assertRaises(ValueError):
            self.check(approved=approved)

    def test_precreation_signature_is_required(self):
        signed = codec.document(self.kw["precreation_raw"], 32768)
        signed["payload"]["invocationId"] = "b" * 32
        from cryptography.exceptions import InvalidSignature
        with self.assertRaises(InvalidSignature):
            self.check(precreation_raw=codec.canonical(signed))

    def test_native_unsigned_cgroup_identity_and_closed_shape(self):
        value, approved = copy.deepcopy(self.value), self.approved.copy()
        value["peers"][peer.ROLE]["cgroup"]["inode"] = p.MAX_U64
        approved["cgroupInode"] = p.MAX_U64
        approved["processIdentitySha256"] = binding.peer_identity(
            {key: val for key, val in approved.items() if key != "processIdentitySha256"})
        self.assertEqual(self.check(value, approved)["cgroupInode"], p.MAX_U64)
        value["peers"][peer.ROLE]["cgroup"]["inode"] = True
        with self.assertRaises(ValueError):
            self.check(value, approved)


if __name__ == "__main__":
    unittest.main()
