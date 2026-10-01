"""Pure closed-protocol controls only: no fabricated or spawned owners."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_execution_protocol as wire

p = g.p


def configuration():
    return {"apiVersion": wire.CONFIGURATION_API, "window": {
        "bootIdBase64url": p.encoded(bytes(range(16))), "timeNamespaceDevice": (1 << 63) + 7,
        "timeNamespaceInode": (1 << 63) + 9, "issuedAtBoottimeNs": "1000000000",
        "startupDeadlineBoottimeNs": "2000000000", "lifetimeDeadlineBoottimeNs": "4000000000",
        "invocationId": "1234567890abcdef1234567890abcdef"}, "expiresAtUnixNanos": 9000000000}


class ProtocolControls(unittest.TestCase):
    def read_configuration(self, value, *, now=1500000000, wall=8000000000, boot=None):
        window = value["window"]
        actual = tuple(window[name] for name in wire.endpoints.WINDOW[:3]) if boot is None else boot
        return wire.configuration(g.canonical(value), boot=actual, now_boottime_ns=now, now_unix_ns=wall)

    def test_configuration_preserves_full_u64_window(self):
        value = configuration()
        self.assertEqual(self.read_configuration(value), value)
        self.assertGreater(value["window"]["timeNamespaceInode"], p.MAX_I64)

    def test_configuration_no_boot_or_interval_renewal(self):
        value = configuration()
        for now in (999999999, 2000000000, 4000000000):
            with self.subTest(now=now), self.assertRaises(ValueError):
                self.read_configuration(value, now=now)
        with self.assertRaises(ValueError):
            self.read_configuration(value, boot=(p.encoded(bytes([9]) * 16), 1, 2))
        with self.assertRaises(ValueError):
            self.read_configuration(value, wall=9000000000)

    def test_configuration_closed_shape_and_reap_reserve(self):
        value = configuration()
        value["futureGeneration"] = "not-authority"
        with self.assertRaises(ValueError): self.read_configuration(value)
        value = configuration()
        value["window"]["timeNamespaceDevice"] = True
        with self.assertRaises(ValueError): self.read_configuration(value)
        value = configuration()
        value["window"]["startupDeadlineBoottimeNs"] = "1600000000"
        value["window"]["lifetimeDeadlineBoottimeNs"] = "1700000000"
        with self.assertRaises(ValueError): self.read_configuration(value)

    def test_exact_window_never_reframes_precreation(self):
        value = configuration()["window"]
        wire.require_window({**value, "configurationSha256": p.sha(b"config")}, value)
        changed = copy.deepcopy(value)
        changed["lifetimeDeadlineBoottimeNs"] = "4000000001"
        with self.assertRaises(ValueError): wire.require_window(changed, value)

    def test_request_is_deterministic_and_literal_originals_survive(self):
        fields = dict(sequence=1, job="parent-start", deadline=(1 << 63) + 10,
            observation={"parent.observation": g.canonical({"inode": (1 << 63) + 1})}, previous=None)
        value, raw = wire.request(**fields)
        self.assertEqual(wire.request(**fields), (value, raw))
        self.assertEqual(value["observation"]["parent.observation"].encode("ascii"), fields["observation"]["parent.observation"])
        self.assertEqual(value["deadlineBoottimeNs"], str((1 << 63) + 10))
        bound = wire.MAX_REQUEST
        try:
            wire.MAX_REQUEST = len(raw)
            with self.assertRaises(ValueError): wire.request(**fields)
            wire.MAX_REQUEST = len(raw) + 1
            self.assertEqual(wire.request(**fields)[1], raw)
        finally:
            wire.MAX_REQUEST = bound

    def test_approval_exact_request_input_and_deadline(self):
        value, raw = wire.request(sequence=2, job="parent-start", deadline=2000000000, observation={}, previous=None)
        digest = p.sha(b"input")
        approved = dict(apiVersion=wire.APPROVAL_API, sequence=2, job=value["job"], requestSha256=p.sha(raw),
            inputSha256=digest, deadlineBoottimeNs=value["deadlineBoottimeNs"])
        self.assertEqual(wire.approval(g.canonical(approved), request_raw=raw, input_sha256=digest), approved)
        for key, alternate in (("sequence", True), ("job", "ordinary-prepare"), ("requestSha256", p.sha(b"other")),
                ("inputSha256", p.sha(b"other")), ("deadlineBoottimeNs", "2000000001")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                wire.approval(g.canonical({**approved, key: alternate}), request_raw=raw, input_sha256=digest)

    def test_owner_action_has_no_commands_fds_or_alternate_purpose(self):
        value = dict(apiVersion=wire.ACTION_API, action="coordinator-finish")
        self.assertEqual(wire.owner_action(g.canonical(value), "coordinator-finish"), value)
        for changed in ({**value, "fd": 9}, {**value, "command": "true"}, {**value, "action": "cleanup"}):
            with self.subTest(value=changed), self.assertRaises(ValueError):
                wire.owner_action(g.canonical(changed), "coordinator-finish")

    def test_native_install_requires_both_exact_predecessors(self):
        role = "publicationGenesis"
        prior = {"native-launch-" + role: {"input": b'{"approved":1}', "result": b'{"bundle":1}'}}
        value = dict(apiVersion="serverware.nativePilotGenesisLaunchInstallationInput/v1", role=role,
            launchInputOriginal='{"approved":1}', bundleOriginal='{"bundle":1}')
        wire.native_install(g.canonical(value), role, prior)
        for key in ("launchInputOriginal", "bundleOriginal"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                wire.native_install(g.canonical({**value, key: '{"other":1}'}), role, prior)
        with self.assertRaises(ValueError):
            wire.native_install(g.canonical({**value, "role": "publicationGenesisCoordinator"}), role, prior)


if __name__ == "__main__":
    unittest.main()
