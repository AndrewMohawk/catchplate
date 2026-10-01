#!/usr/bin/env python3
"""Eight deterministic SYNTHETIC public-grammar controls, not kernel evidence.

No protected owner, process, descriptor, filesystem, signer, or clock is used.
These controls cannot establish retention, execution or peer admission.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import native_pilot_peer_preparation as profile


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("ascii")


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def fixture(kind="ordinary-services"):
    rows = {}
    for index, role in enumerate(profile.ROLES[kind]):
        rows[role] = dict(processId=41000 + index, startTimeTicks=51000 + index,
            pidfd=dict(device=4, inode=61000 + index),
            targetExecutable=dict(device=8, inode=71000 + index, length=8192,
                sha256=sha(("SYNTHETIC target " + role).encode("ascii"))),
            cgroup=dict(pathSha256=sha(b"/SYNTHETIC/retained-peer"), mountId=31, inode=81000))
    return dict(apiVersion="serverware.nativePilotPeerPreparation/v1", profile="retain-observed-cgroup",
        ownerKind=kind, phase="executing-gate" if kind == "gate" else "parked-pre-exec",
        configurationSha256=sha(b"SYNTHETIC cold configuration"),
        sourceOriginalSha256=sha(b"SYNTHETIC owner source original"),
        bootIdBase64url=base64.urlsafe_b64encode(bytes(range(16))).rstrip(b"=").decode("ascii"),
        timeNamespaceDevice=4, timeNamespaceInode=91000, issuedAtBoottimeNs="1000000000",
        observedAtBoottimeNs="2000000000", startupDeadlineBoottimeNs="20000000000",
        lifetimeDeadlineBoottimeNs="40000000000", invocationId="SYNTHETIC-peer-preparation",
        peers=rows)


class PeerPreparationControls(unittest.TestCase):
    def rejected(self, value):
        with self.assertRaises((ValueError, TypeError, UnicodeError)):
            profile.shape(canonical(value))

    def test_all_three_closed_observation_profiles(self):
        self.assertEqual(tuple(map(len, profile.ROLES.values())), (5, 10, 1))
        for kind in profile.ROLES:
            original = fixture(kind)
            checked = profile.shape(canonical(original))
            self.assertEqual(checked, original)
            checked["peers"].clear()
            self.assertTrue(original["peers"])

    def test_cgroup_hash_is_exact_path_not_proc_original(self):
        raw = b"7:memory:/legacy\n0::/SYNTHETIC/retained-peer\n"
        path = profile.cgroup_path(raw)
        self.assertEqual(path, "/SYNTHETIC/retained-peer")
        self.assertEqual(sha(path.encode()), fixture()["peers"][profile.ROLES["ordinary-services"][0]]["cgroup"]["pathSha256"])
        self.assertNotEqual(sha(raw), sha(path.encode()))
        self.assertEqual(profile.cgroup_path(b"0::/\n"), "/")

    def test_ambiguous_traversal_and_unbounded_membership_refused(self):
        for raw in (b"", b"1:memory:/only-v1\n", b"0::/a\n0::/a\n", b"0::relative\n",
                b"0::/a/../b\n", b"0::/./a\n", b"0::/a//b\n", b"0::/a\0b\n",
                b"0::/" + b"a" * 4096, b"x" * 16385, b"0::/\xff\n"):
            with self.subTest(raw=raw[:32]), self.assertRaises((ValueError, UnicodeError)):
                profile.cgroup_path(raw)

    def test_migration_or_replaced_mount_and_inode_refused(self):
        expected = dict(pathSha256=sha(b"/SYNTHETIC/original"), mountId=31, inode=101)
        self.assertIsNone(profile.require_same_cgroup(expected, copy.deepcopy(expected)))
        for name, new in (("pathSha256", sha(b"/SYNTHETIC/moved")), ("mountId", 32), ("inode", 102)):
            actual = dict(expected, **{name: new})
            with self.assertRaises(ValueError):
                profile.require_same_cgroup(expected, actual)

    def test_phase_version_and_final_claims_are_not_observations(self):
        for name, new in (("apiVersion", "serverware.nativePilotPeerPreparation/v2"),
                ("profile", "allow-migration"), ("phase", "executing-gate"),
                ("ownerKind", "caller-supplied")):
            value = fixture(); value[name] = new; self.rejected(value)
        for name, new in (("uid", 31001), ("securityLabelSha256", sha(b"invented label")),
                ("configurationGenerationSha256", sha(b"invented generation")), ("ready", True)):
            value = fixture(); value["peers"][profile.ROLES["ordinary-services"][0]][name] = new
            self.rejected(value)

    def test_exact_role_inventory_and_unique_process_ownership(self):
        value = fixture(); first, second = profile.ROLES["ordinary-services"][:2]
        value["peers"].pop(first); self.rejected(value)
        value = fixture(); value["peers"]["external-signer"] = copy.deepcopy(value["peers"][first]); self.rejected(value)
        for name in ("processId", "pidfd"):
            value = fixture(); value["peers"][second][name] = copy.deepcopy(value["peers"][first][name]); self.rejected(value)

    def test_u64_exactness_and_invalid_scalars(self):
        value = fixture(); first = profile.ROLES["ordinary-services"][0]
        value["peers"][first]["startTimeTicks"] = (1 << 64) - 1
        self.assertEqual(profile.shape(canonical(value)), value)
        for name, new in (("processId", True), ("processId", 1), ("startTimeTicks", 0),
                ("startTimeTicks", 1 << 64)):
            value = fixture(); value["peers"][first][name] = new; self.rejected(value)
        for name, new in (("length", 0), ("inode", 0), ("length", 256 * 1024 * 1024 + 1), ("sha256", None)):
            value = fixture(); value["peers"][first]["targetExecutable"][name] = new; self.rejected(value)

    def test_original_time_and_canonical_byte_bounds(self):
        for name, new in (("observedAtBoottimeNs", "999999999"),
                ("observedAtBoottimeNs", "20000000000"), ("lifetimeDeadlineBoottimeNs", "19999999999"),
                ("issuedAtBoottimeNs", "01"), ("observedAtBoottimeNs", 2000000000)):
            value = fixture(); value[name] = new; self.rejected(value)
        raw = canonical(fixture())
        for original in (raw + b"\n", b" " * 65537, raw[:-1] + b',"profile":"retain-observed-cgroup"}'):
            with self.assertRaises(ValueError):
                profile.shape(original)


if __name__ == "__main__":
    unittest.main()
