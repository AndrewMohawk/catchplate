#!/usr/bin/env python3
"""Eight pure endpoint protocol controls; no owner/process/socket is fabricated.

All process, directory and file identities below are labelled synthetic data.
These controls do not exercise Linux ownership, protected input intake, fsync,
fs-verity, native admission, service readiness or actual child cleanup.
"""
from __future__ import annotations

import copy
from pathlib import Path
import stat
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from cryptography.exceptions import InvalidSignature
import test_native_pilot_genesis_delivery as transcripts
import test_native_pilot_genesis_parent_authority as parents
from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_endpoint_profile as wire
from catchplate import native_pilot_genesis_endpoint_control as control

p = g.p


class EndpointProtocolTests(unittest.TestCase):
    def setUp(self):
        self.f = transcripts.fixture()
        self.source = self.f["input"]
        self.config_raw = self.source["ownerConfigurationOriginal"].encode("ascii")
        self.preparation_raw = self.source["preparationOriginal"].encode("ascii")
        self.resources_raw = self.source["resourcesOriginal"].encode("ascii")
        self.preparation = wire.preparation(self.preparation_raw)
        self.observation_raw = self.preparation["observationOriginal"].encode("ascii")

    def test_control_is_exact_pinned_executable_and_configuration(self):
        value = {"apiVersion": wire.CONTROL_API, "controllerExecutableSha256": p.sha(b"synthetic-controller"),
            "configurationSha256": p.sha(self.config_raw)}
        self.assertEqual(control.control(g.canonical(value)), value)
        for name in ("apiVersion", "controllerExecutableSha256", "extra"):
            changed = copy.deepcopy(value); changed[name] = "unknown"
            with self.assertRaises(ValueError):
                control.control(g.canonical(changed))

    def test_only_two_cold_endpoint_roles_are_selected(self):
        value = wire.configuration(self.config_raw)
        self.assertEqual(set(value["services"]), set(wire.ROLES))
        value["services"]["retrieval"] = value["services"].pop(wire.ROLES[0])
        with self.assertRaises(ValueError):
            wire.configuration(g.canonical(value))

    def test_observation_rejects_pid_pidfd_and_executable_aliases(self):
        original = wire.observation(self.observation_raw)
        for field in ("processId", "pidfdInode", "executable"):
            value = copy.deepcopy(original)
            value["services"][wire.ROLES[1]][field] = value["services"][wire.ROLES[0]][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                wire.observation(g.canonical(value))

    def test_preparation_requires_actual_observation_and_closed_cgroup(self):
        for field in ("processId", "targetExecutable", "cgroup"):
            value = copy.deepcopy(self.preparation)
            row = value["services"][wire.ROLES[0]]
            if field == "processId": row[field] += 1
            elif field == "targetExecutable": row[field]["inode"] += 1
            else: row[field]["inventedOwner"] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                wire.preparation(g.canonical(value))

    def test_resources_preserve_socket_fstat_and_exact_store_inventory(self):
        original = wire.resources(self.resources_raw)
        listener = original["services"][wire.ROLES[0]]["activation"][0]
        self.assertEqual((listener["uid"], listener["gid"]), (0, 0))
        self.assertTrue(stat.S_ISSOCK(listener["mode"]))
        for change in ("count", "alias", "boolean"):
            value = copy.deepcopy(original)
            row = value["services"][wire.ROLES[0]]
            if change == "count": row["directories"]["ledger-spool-store"]["entryCount"] = 0
            elif change == "alias": row["activation"][1]["inode"] = row["activation"][0]["inode"]
            else: row["directories"]["retrieval-objects"]["identity"]["mountId"] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                wire.resources(g.canonical(value))

    def test_original_parent_window_is_not_renewed(self):
        parent = self.source["parentOriginals"]
        args = dict(configuration_raw=self.config_raw, preparation_raw=self.preparation_raw, resources_raw=self.resources_raw,
            parent_configuration_raw=parent["parentConfigurationOriginal"].encode("ascii"),
            parent_delivery_configuration_raw=parent["parentDeliveryConfigurationOriginal"].encode("ascii"),
            parent_precreation_raw=parent["parentPrecreationOriginal"].encode("ascii"),
            parent_observation_raw=parent["parentObservationOriginal"].encode("ascii"), boot=self.f["boot"])
        self.assertEqual(wire.context(**args, now_boottime_ns=self.f["now"])["deadline"], 5_000_000_000)
        for now in (999_999_999, 5_000_000_000):
            with self.assertRaises(ValueError):
                wire.context(**args, now_boottime_ns=now)

    def test_release_uses_its_own_native_signature_domain(self):
        config = wire.configuration(self.config_raw)
        payload = {"configurationSha256": p.sha(self.config_raw),
            "parentConfigurationSha256": config["parentConfigurationSha256"],
            "parentPrecreationSha256": config["parentPrecreationSha256"],
            "observationSha256": p.sha(self.observation_raw), "invocationId": self.preparation["invocationId"],
            "signingKeyId": config["releaseAuthority"]["keyId"], "services": {role: {
                "launch": parents.pin("synthetic-" + role), "image": config["services"][role]["image"]} for role in wire.ROLES}}
        key = parents.selected_key(8)[0]
        raw = parents.independently_signed(wire.RELEASE_API, wire.RELEASE_DOMAIN, payload, key)
        kwargs = dict(configuration_raw=self.config_raw, observation_raw=self.observation_raw)
        self.assertEqual(control.release_original(raw, **kwargs), payload)
        wrong = parents.independently_signed(wire.RELEASE_API, parents.authority.RELEASE_DOMAIN, payload, key)
        with self.assertRaises(InvalidSignature):
            control.release_original(wrong, **kwargs)

    def test_store_requires_literal_genesis_bound_to_actual_c9_source(self):
        context = transcripts.authority.verified_delivery(wire.ROLES[0], g.canonical(self.source), self.f["raw"],
            boot=self.f["boot"], now_boottime_ns=self.f["now"])
        proof = g.canonical({"syntheticProofOnly": True})
        genesis = g.canonical({"apiVersion": "catchplate.nativeLedgerSpoolStoreGenesis/v1", "guest": context["guest"],
            "proofScopeSha256": p.sha(proof)})
        directory = wire.resources(self.resources_raw)["services"][wire.ROLES[0]]["activation"][2]
        value = {"apiVersion": wire.STORE_API, "resourcesSha256": p.sha(self.resources_raw), "deliverySha256": p.sha(self.f["raw"]),
            "proofScopeSha256": p.sha(proof), "genesisOriginal": genesis.decode("ascii"),
            "genesisFile": {"device": directory["device"], "inode": 999, "mode": stat.S_IFREG | 0o400,
                "uid": context["guest"]["uid"], "gid": context["guest"]["gid"], "length": len(genesis), "sha256": p.sha(genesis)},
            "store": {"genesisSha256": p.sha(genesis), "sequence": 0, "headSha256": p.sha(genesis)}}
        kwargs = dict(resources_raw=self.resources_raw, delivery_raw=self.f["raw"], proof_scope_raw=proof)
        self.assertEqual(wire.store_observation(g.canonical(value), **kwargs), value["store"])
        value["store"]["sequence"] = 1
        with self.assertRaises(ValueError):
            wire.store_observation(g.canonical(value), **kwargs)


if __name__ == "__main__":
    unittest.main()
