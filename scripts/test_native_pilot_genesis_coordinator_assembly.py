#!/usr/bin/env python3
"""Pure synthetic assembly transcripts, never process or resource owners.

Existing signed test histories and ordinary grants authenticate public bytes.
Every PID, PIDFD, cgroup, activation and path here is labelled fixture data;
no service, protected FD, image, journal, signer or native admission is run.
"""
from __future__ import annotations

import copy
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

import test_native_pilot_genesis_delivery as deliveries
import test_native_pilot_genesis_ordinary_runtime as ordinary_tests
import test_native_pilot_genesis_coordinator_runtime as runtime_tests
from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_coordinator_assembly as assembly

p = g.p


def digest(label):
    return p.sha(("SYNTHETIC ASSEMBLY ONLY / " + label).encode("ascii"))


def measured(peer, ordinal):
    return {"processId": peer["pid"], "startTimeTicks": peer["startTimeTicks"],
        "pidfd": {"device": 7, "inode": 8000 + ordinal},
        "targetExecutable": {name: peer["executable" + name[0].upper() + name[1:]]
            for name in ("device", "inode", "length", "sha256")},
        "cgroup": {"pathSha256": peer["cgroupPathSha256"], "mountId": peer["cgroupMountId"], "inode": peer["cgroupInode"]}}


def fixture():
    f = ordinary_tests.fixture()
    parent = f["f"]["parent"]
    approved_peers, ordinary_records, native_records = {}, {}, {}
    for role in assembly.runtime.ROLES:
        prepared = ordinary_tests.authority.prepare_input("grant", g.canonical(f["grants"][role]), **f["kw"])
        raw = ordinary_tests.signed_grant(prepared["payload"], f["f"]["rows"][role]["keys"]["root"])
        ordinary_records[role] = {"runtimeOriginal": f["runtimes"][role].decode("ascii"),
            "historyOriginal": f["build_args"]["history_originals"][role].decode("ascii"),
            "grantOriginal": raw.decode("ascii"), "guest": prepared["payload"]["guest"]}
        approved_peers[role] = deliveries.peer(1, 2, identity=f["f"]["rows"][role]["identity"])
    originals = f["grants"][assembly.runtime.ROLES[0]]
    for index, (role, source) in enumerate(((assembly.endpoints.ROLES[1], "nativePublicationOriginal"),
            (assembly.endpoints.ROLES[0], "nativeRetrievalOriginal"))):
        raw = originals[source]
        guest = g.document(raw.encode("ascii"), g.MAX_BYTES)["payload"]["authorization"]["guest"]
        native_records[role] = {"grantOriginal": raw, "guest": guest}
        peer = deliveries.peer(guest["uid"], 5000 + index)
        peer["gid"] = guest["gid"]
        approved_peers[role] = runtime_tests.rehash_peer(peer)
    approved_peers["resultPeer"] = deliveries.peer(0, 6000)
    pins = {name: digest(name) for name in assembly.PINS}
    window = g.document(parent["precreation_raw"], 32768)["payload"]
    observation = {"apiVersion": assembly.OBSERVATION, **pins,
        "window": {name: window[name] for name in assembly.endpoints.WINDOW},
        "observedAtBoottimeNs": str(f["kw"]["now_boottime_ns"]),
        "peers": {role: measured(approved_peers[role], index) for index, role in enumerate(assembly.ROLES)},
        "activation": [{"name": name, "fd": slot, "device": 9, "inode": 9000 + slot,
            "mode": kind | (0o777 if kind == stat.S_IFSOCK else 0o711), "uid": 0, "gid": 0}
            for slot, (name, kind) in enumerate(assembly.runtime.ACTIVATION, 6)]}
    approved = {"apiVersion": assembly.API, **pins, "peers": approved_peers}
    return dict(approval_raw=g.canonical(approved), observation_raw=g.canonical(observation),
        ordinary_records=ordinary_records, native_records=native_records,
        cold=g.document(parent["cold_raw"], 65536), coordinator=g.document(parent["observation_raw"], 32768), **f["kw"])


class GenesisCoordinatorAssemblyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.f = fixture()

    def value(self): return copy.deepcopy(self.f)

    def refused(self, value):
        with self.assertRaises((ValueError, InvalidSignature, KeyError, TypeError)):
            assembly.build(**value)

    def test_complete_public_composition_preserves_exact_authenticated_originals(self):
        result = assembly.build(**self.value())
        runtime = g.document(result["runtimeOriginal"], g.MAX_BYTES)
        self.assertEqual(runtime["apiVersion"], assembly.runtime.API)
        self.assertEqual(tuple(row["serviceRole"] for row in runtime["histories"]), assembly.runtime.ROLES)
        for index, role in enumerate(assembly.runtime.ROLES):
            row = self.f["ordinary_records"][role]
            self.assertEqual(runtime["histories"][index]["historyOriginal"], row["historyOriginal"])
            self.assertEqual(runtime[("durableGrantOriginal", "currentGrantOriginal")[index]], row["grantOriginal"])
        self.assertEqual(len(runtime["nativeEndpoints"]), 2)
        self.assertNotIn("ready", result)
        self.assertNotIn("cleanupComplete", result)

    def test_approval_is_closed_and_pins_all_four_originals(self):
        for name in (*assembly.PINS, "unapprovedFallback"):
            value = self.value(); approved = g.document(value["approval_raw"], 65536)
            approved[name] = digest("replacement")
            value["approval_raw"] = g.canonical(approved)
            with self.subTest(field=name): self.refused(value)
        value = self.value(); approved = g.document(value["approval_raw"], 65536)
        approved["apiVersion"] = assembly.OBSERVATION; value["approval_raw"] = g.canonical(approved)
        self.refused(value)

    def test_observation_requires_five_distinct_actual_identity_rows(self):
        for field in ("processId", "pidfd", "extraRole"):
            value = self.value(); observed = g.document(value["observation_raw"], 65536)
            first, second = (observed["peers"][role] for role in assembly.ROLES[:2])
            if field == "extraRole": observed["peers"][field] = copy.deepcopy(first)
            else: second[field] = copy.deepcopy(first[field])
            value["observation_raw"] = g.canonical(observed)
            with self.subTest(field=field): self.refused(value)

    def test_exact_ten_activation_rows_and_native_result_pair_positions(self):
        for what in ("count", "fd", "kind", "root", "alias", "result-name"):
            value = self.value(); observed = g.document(value["observation_raw"], 65536)
            rows = observed["activation"]
            if what == "count": rows.pop()
            elif what == "fd": rows[0]["fd"] = True
            elif what == "kind": rows[0]["mode"] = stat.S_IFREG | 0o400
            elif what == "root": rows[0]["uid"] = 1000
            elif what == "alias": rows[-1]["inode"] = rows[0]["inode"]
            else: rows[-1]["name"] = "caller-invented-result"
            value["observation_raw"] = g.canonical(observed)
            with self.subTest(which=what): self.refused(value)

    def test_valid_peer_digest_still_requires_measured_process_and_cgroup(self):
        role = assembly.ROLES[0]
        for name in ("pid", "startTimeTicks", "executableInode", "cgroupInode", "uid"):
            value = self.value(); approved = g.document(value["approval_raw"], 65536)
            peer = approved["peers"][role]; peer[name] += 1
            runtime_tests.rehash_peer(peer)
            value["approval_raw"] = g.canonical(approved)
            with self.subTest(field=name): self.refused(value)

    def test_root_result_peer_requires_the_exact_observed_native_controller(self):
        result = assembly.build(**self.value())
        actual = g.document(result["runtimeOriginal"], g.MAX_BYTES)["resultPeer"]
        self.assertEqual((actual["uid"], actual["gid"]), (0, 0))
        self.assertEqual(actual, g.document(self.f["approval_raw"], 65536)["peers"]["resultPeer"])
        for name in ("pid", "startTimeTicks", "executableInode", "cgroupInode", "uid", "gid"):
            value = self.value(); approved = g.document(value["approval_raw"], 65536)
            replacement = approved["peers"]["resultPeer"]
            replacement[name] += 1
            runtime_tests.rehash_peer(replacement)
            value["approval_raw"] = g.canonical(approved)
            with self.subTest(field=name): self.refused(value)

    def test_native_originals_are_pinned_by_both_ordinary_grants(self):
        for role in assembly.endpoints.ROLES:
            value = self.value(); row = value["native_records"][role]
            signed = g.document(row["grantOriginal"].encode("ascii"), g.MAX_BYTES)
            signed["signature"] = p.encoded(bytes(64)); row["grantOriginal"] = g.canonical(signed).decode("ascii")
            self.refused(value)
            value = self.value(); value["native_records"][role]["guest"]["uid"] += 1
            self.refused(value)
        value = self.value(); a, b = assembly.endpoints.ROLES
        value["native_records"][a] = copy.deepcopy(value["native_records"][b]); self.refused(value)

    def test_root_signatures_and_runtime_history_originals_cannot_be_substituted(self):
        for role in assembly.runtime.ROLES:
            value = self.value(); row = value["ordinary_records"][role]
            signed = g.document(row["grantOriginal"].encode("ascii"), 262144)
            signed["signatureBase64url"] = p.encoded(bytes(64)); row["grantOriginal"] = g.canonical(signed).decode("ascii")
            self.refused(value)
        value = self.value(); a, b = assembly.runtime.ROLES
        value["ordinary_records"][a]["historyOriginal"] = value["ordinary_records"][b]["historyOriginal"]
        self.refused(value)

    def test_original_startup_boot_and_native_unix_caps_never_renew(self):
        value = self.value(); observed = g.document(value["observation_raw"], 65536)
        observed["window"]["startupDeadlineBoottimeNs"] = "4000000000"
        value["observation_raw"] = g.canonical(observed)
        result = assembly.build(**value)
        self.assertEqual(result["deadline"], 4_000_000_000)
        self.assertGreater(result["runtimeDeadline"], result["deadline"])
        later = copy.deepcopy(value); later["now_boottime_ns"] += 1
        self.assertEqual(assembly.build(**later), result)
        for name, replacement in (("now_boottime_ns", 4_000_000_000),
                ("now_unix_ns", result["epochLimit"]), ("now_unix_ns", result["epochFloor"] - 1),
                ("boot", (p.encoded(bytes([91]) * 16), *value["boot"][1:]))):
            changed = copy.deepcopy(value); changed[name] = replacement
            with self.subTest(field=name, value=replacement): self.refused(changed)


if __name__ == "__main__": unittest.main()
