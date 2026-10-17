"""Pure closed-protocol controls only: no fabricated or spawned owners."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_execution_protocol as wire
from catchplate import native_pilot_genesis_jobs as jobs

p = g.p


def configuration():
    return {"apiVersion": wire.CONFIGURATION_API, "window": {
        "bootIdBase64url": p.encoded(bytes(range(16))), "timeNamespaceDevice": (1 << 63) + 7,
        "timeNamespaceInode": (1 << 63) + 9, "issuedAtBoottimeNs": "1000000000",
        "startupDeadlineBoottimeNs": "2000000000", "lifetimeDeadlineBoottimeNs": "4000000000",
        "invocationId": "1234567890abcdef1234567890abcdef"}, "expiresAtUnixNanos": 9000000000}


class ProtocolControls(unittest.TestCase):
    def read_configuration(self, value, *, now=1500000000, wall=8000000000, boot=None, handoff=False):
        window = value["window"]
        actual = tuple(window[name] for name in wire.endpoints.WINDOW[:3]) if boot is None else boot
        return wire.configuration(g.canonical(value), boot=actual, now_boottime_ns=now, now_unix_ns=wall, handoff=handoff)

    def test_handoff_configuration_is_explicit_and_peer_is_independently_fixed(self):
        value = configuration()
        value.update(apiVersion=wire.HANDOFF_CONFIGURATION_API, coreHandoff={"peerPid": 123, "peerUid": 0, "peerGid": 0})
        self.assertEqual(self.read_configuration(value, handoff=True), value)
        with self.assertRaises(ValueError): self.read_configuration(value)
        with self.assertRaises(ValueError): self.read_configuration(configuration(), handoff=True)
        for peer in ({"peerPid": True, "peerUid": 0, "peerGid": 0},
                {"peerPid": 123, "peerUid": 1, "peerGid": 0}, {"peerPid": 123, "peerUid": 0, "peerGid": False},
                {"peerPid": 0, "peerUid": 0, "peerGid": 0}, {"peerPid": 1, "peerUid": 0, "peerGid": 0},
                {"peerPid": 123, "peerUid": 0, "peerGid": 0, "path": "/tmp/core"}):
            with self.subTest(peer=peer), self.assertRaises(ValueError):
                self.read_configuration({**value, "coreHandoff": peer}, handoff=True)

    def test_handoff_graph_acquires_before_cleanup_and_transfers_after(self):
        self.assertEqual(len(jobs.JOBS), 64)
        self.assertEqual(len(jobs.HANDOFF_JOBS), 66)
        self.assertEqual(jobs.HANDOFF_JOBS[:-3], jobs.JOBS[:-1])
        self.assertEqual(tuple(job.name for job in jobs.HANDOFF_JOBS[-4:]),
            ("coordinator-finish", "acquire-cold-core", "cleanup", "handoff-cold-core"))
        self.assertEqual(tuple(job.key for job in jobs.HANDOFF_JOBS if job.key is not None), jobs.KEY_PURPOSES)
        for name in ("acquire-cold-core", "handoff-cold-core"):
            with self.assertRaises(ValueError): jobs.job(name)
            self.assertEqual(jobs.job(name, handoff=True).family, "owner")

    def test_handoff_request_approval_profile_cannot_be_downgraded(self):
        value, raw = wire.request(sequence=66, job="handoff-cold-core", deadline=3999999999,
            observation={}, previous=None, handoff=True)
        approved = dict(apiVersion=wire.HANDOFF_APPROVAL_API, sequence=66, job=value["job"], requestSha256=p.sha(raw),
            inputSha256=p.sha(b"input"), deadlineBoottimeNs=value["deadlineBoottimeNs"])
        self.assertEqual(wire.approval(g.canonical(approved), request_raw=raw, input_sha256=p.sha(b"input")), approved)
        with self.assertRaises(ValueError):
            wire.approval(g.canonical({**approved, "apiVersion": wire.APPROVAL_API}), request_raw=raw, input_sha256=p.sha(b"input"))

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
        value = dict(apiVersion="catchplate.nativePilotGenesisLaunchInstallationInput/v1", role=role,
            launchInputOriginal='{"approved":1}', bundleOriginal='{"bundle":1}')
        wire.native_install(g.canonical(value), role, prior)
        for key in ("launchInputOriginal", "bundleOriginal"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                wire.native_install(g.canonical({**value, key: '{"other":1}'}), role, prior)
        with self.assertRaises(ValueError):
            wire.native_install(g.canonical({**value, "role": "publicationGenesisCoordinator"}), role, prior)


if __name__ == "__main__":
    unittest.main()
