#!/usr/bin/env python3
"""Complete cold Runtime/v2 public transcripts, never native owner admission.

The fixture carries genuine-format synthetic C9, ordinary histories and root
grant signatures. All PIDs, descriptors, labels and resources are test data.
No kernel peer, key import, image, protected signer or native service runs.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

import test_native_pilot_genesis_delivery as deliveries
from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_coordinator_runtime as runtime
from serverware import native_pilot_genesis_delivery_authority as delivery

p = g.p


def digest(label):
    return p.sha(("SYNTHETIC COORDINATOR RUNTIME / " + label).encode("ascii"))


def rehash_peer(value):
    """Independent native peer framing, not an owner or validator bypass."""
    parts = [value[name].to_bytes(width, "big") for name, width in (("uid", 4), ("gid", 4), ("pid", 4),
        ("startTimeTicks", 8), ("executableDevice", 8), ("executableInode", 8), ("executableLength", 8))]
    parts += [bytes.fromhex(value["executableSha256"].removeprefix("sha256:")), value["cgroupPathSha256"].encode("ascii"),
        value["cgroupMountId"].to_bytes(8, "big"), value["cgroupInode"].to_bytes(8, "big"),
        value["securityLabelSha256"].encode("ascii"), value["configurationGenerationSha256"].encode("ascii")]
    value["processIdentitySha256"] = p.framed(b"serverware.policyCustodyPeerProcessIdentity/v4", parts)
    return value


class GenesisCoordinatorRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = deliveries.fixture("publicationGenesisCoordinator")

    def value(self):
        return g.document(self.f["runtime_raw"], g.MAX_BYTES)

    def validate(self, value=None, **changes):
        context = dict(window=self.f["window"], coordinator=self.f["observed"], cold=self.f["configuration"],
            boot=self.f["boot"], now_boottime_ns=self.f["now"])
        context.update(changes)
        return runtime.validate(g.canonical(self.value() if value is None else value), **context)

    def refused(self, value=None, **changes):
        with self.assertRaises((ValueError, InvalidSignature, KeyError, TypeError)):
            self.validate(value, **changes)

    def test_complete_runtime_authenticates_histories_grants_and_exact_c9(self):
        checked = self.validate()
        held = delivery.verified_delivery("publicationGenesisCoordinator", p.canonical(self.f["input"]),
            self.f["raw"], boot=self.f["boot"], now_boottime_ns=self.f["now"])
        self.assertEqual(checked["runtime"], self.value())
        self.assertLessEqual(held["deadline"], checked["deadline"])
        self.assertEqual(held["guest"]["runtimeConfigurationSha256"], p.sha(self.f["runtime_raw"]))
        self.assertEqual(tuple(row["serviceRole"] for row in checked["runtime"]["histories"]), runtime.ROLES)
        for row, session in zip(checked["runtime"]["histories"], checked["runtime"]["serviceSessions"], strict=True):
            wrapper = g.document(row["historyOriginal"].encode("ascii"), g.MAX_BYTES)
            identity = wrapper["history"]["firstRetainedEpoch"]["retainedEpoch"]["endpointProcessIdentity"]
            # Both digests are independently valid, not interchangeable domains.
            self.assertNotEqual(session["expectedPeer"]["processIdentitySha256"], identity["identitySha256"])
            self.assertEqual(session["expectedPeer"]["pid"], identity["endpointPid"])
        self.assertNotIn("generationAdmission", checked["runtime"])

    def test_only_late_cold_runtime_profile_and_exact_lists_are_accepted(self):
        for api in ("serverware.nativePublicationGenesisCoordinatorRuntime/v1",
                "serverware.nativePublicationGenesisBootstrapRuntime/v1", "serverware.policyCustodyProductionRpcRuntime/v14"):
            value = self.value(); value["apiVersion"] = api; self.refused(value)
        for name in ("histories", "serviceSessions", "nativeEndpoints"):
            value = self.value(); value[name].append(copy.deepcopy(value[name][0])); self.refused(value)
        value = self.value(); value["optionalHotFallback"] = None; self.refused(value)

    def test_both_ordinary_grants_require_exact_root_signatures_and_role(self):
        for name in ("durableGrantOriginal", "currentGrantOriginal"):
            value = self.value(); signed = g.document(value[name].encode("ascii"), 262144)
            signed["signatureBase64url"] = p.encoded(bytes(64))
            value[name] = g.canonical(signed).decode("ascii"); self.refused(value)
            value = self.value(); value[name] = g.canonical(signed["payload"]).decode("ascii"); self.refused(value)
        value = self.value(); value["durableGrantOriginal"] = value["currentGrantOriginal"]; self.refused(value)

    def test_history_signature_root_pin_and_runtime_original_are_not_substitutable(self):
        value = self.value(); value["histories"][0]["rootKeySpkiSha256"] = digest("other-root"); self.refused(value)
        value = self.value(); value["histories"][0]["historyOriginal"] = value["histories"][1]["historyOriginal"]; self.refused(value)
        value = self.value(); value["histories"][0]["runtimeOriginal"] = value["histories"][1]["runtimeOriginal"]; self.refused(value)
        value = self.value()
        wrapper = g.document(value["histories"][0]["historyOriginal"].encode("ascii"), g.MAX_BYTES)
        wrapper["history"]["firstRetainedEpoch"]["rootSignatureBase64"] = p.encoded(bytes(64))
        value["histories"][0]["historyOriginal"] = g.canonical(wrapper).decode("ascii"); self.refused(value)

    def test_valid_peer_digest_cannot_replace_authenticated_service_process_fields(self):
        for field in ("pid", "startTimeTicks", "executableDevice", "executableInode", "executableLength", "executableSha256"):
            value = self.value(); peer = value["serviceSessions"][0]["expectedPeer"]
            peer[field] = digest("other-executable") if field.endswith("Sha256") else peer[field] + 1
            rehash_peer(peer)
            with self.subTest(field=field): self.refused(value)

    def test_coordinator_observation_and_common_expected_peer_are_exact(self):
        for field in ("processId", "startTimeTicks"):
            observed = copy.deepcopy(self.f["observed"]); observed[field] += 1
            self.refused(coordinator=observed)
        observed = copy.deepcopy(self.f["observed"]); observed["executable"]["inode"] += 1
        self.refused(coordinator=observed)
        value = self.value(); value["serviceSessions"][0]["expectedSocketPath"] = "/run/not-the-cold-service.sock"
        self.refused(value)

    def test_scope_original_clock_and_root_result_peer_bounds_are_preserved(self):
        for field, replacement in (("commissioningIdSha256", digest("other-commissioning")),
                ("expiresAtBoottimeNanos", 99_000_000_000)):
            value = self.value(); value["scope"][field] = replacement; self.refused(value)
        self.refused(now_boottime_ns=5_000_000_000)
        self.refused(boot=(p.encoded(bytes([81]) * 16), *self.f["boot"][1:]))
        value = self.value(); value["resultPeer"]["uid"] = 1; rehash_peer(value["resultPeer"]); self.refused(value)
        value = self.value(); value["resultPeer"]["pid"] = self.f["observed"]["processId"]
        rehash_peer(value["resultPeer"]); self.refused(value)

    def test_c9_retains_exact_ten_activation_slots_and_parent_result_pair(self):
        for which in ("name", "slot", "alias", "result"):
            value = copy.deepcopy(self.f["input"])
            payload = g.document(value["payloadOriginal"].encode("ascii"), 65536)
            rows = payload["activation"]
            if which == "name": rows[0]["name"] = "other-session"
            elif which == "slot": rows[0]["fd"] += 1
            elif which == "alias": rows[1]["device"], rows[1]["inode"] = rows[0]["device"], rows[0]["inode"]
            else: rows[-1]["inode"] += 1
            value["activationOriginal"] = g.canonical(rows).decode("ascii")
            payload["activation"] = rows; value["payloadOriginal"] = g.canonical(payload).decode("ascii")
            with self.subTest(which=which), self.assertRaises((ValueError, KeyError, TypeError)):
                delivery.prepare_input("publicationGenesisCoordinator", p.canonical(value),
                    boot=self.f["boot"], now_boottime_ns=self.f["now"])


if __name__ == "__main__": unittest.main()
