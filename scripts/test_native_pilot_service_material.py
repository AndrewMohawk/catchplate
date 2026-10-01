#!/usr/bin/env python3
"""Bounded synthetic material controls, not live installation or initialization.

Persistence uses an authenticated deterministic public test grant. Generation
material is only a labelled genesis projection: it does not claim five genuine
ordinary histories, full bundle admission, owner provenance or an empty journal.
No installer, protected file, runtime service or signing entrypoint is invoked.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))
from serverware import native_pilot_service_material as material
from serverware import native_pilot_publication_profiles as publication
from serverware import native_pilot_native_service_profile as services
from test_native_pilot_endpoint_launches import (fixture, pair, service_fixture, service_policy,
    policy_fragment as launch_policy, clocks)
from test_native_pilot_closure_set import canonical, sha, synthetic
from test_native_pilot_generation_scope import encoded

SLOTS = {"native-persistence-configuration": 512 * 1024, "native-persistence-genesis": 16384,
    "native-persistence-journal": 1024, "native-generation-install-genesis": 512 * 1024}
POLICY = {"apiVersion": "serverware.nativePilotServiceMaterialPolicy/v1", "initialization": "fresh-persistence-and-generation"}


class ServiceMaterialControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = fixture()
        cls.service = service_fixture(cls.f, "persistence", pair(cls.f, "persistence"), service_policy(), launch_policy())
        cls.persistence = json.loads(cls.service["inputOriginal"])
        # This is explicitly a grammar/projection fixture, not a signed
        # generation history or permission to initialize a real journal.
        cls.generation = {"genesisOriginal": canonical({"apiVersion": "serverware.nativeGenerationCoordinatorGenesis/v1",
            "guest": cls.f["guests"]["generationInstall"], "assignmentPayloadSha256": synthetic("projection-only-assignment"),
            "servicesSha256": synthetic("projection-only-five-services")}).decode("ascii"), "recordOriginals": []}

    def values(self):
        return {"persistence": copy.deepcopy(self.persistence), "generationInstall": copy.deepcopy(self.generation)}

    def test_explicit_fresh_policy_has_no_paths_or_history_defaults(self):
        self.assertEqual(material.validate_policy(POLICY), POLICY)
        for value in ({}, POLICY | {"approved": True}, POLICY | {"initialization": None},
                POLICY | {"initialization": "restore-existing-journals"}, POLICY | {"apiVersion": POLICY["apiVersion"] + "-unknown"}):
            with self.assertRaises(ValueError): material.validate_policy(value)

    def test_exact_four_closed_fixed_publication_profiles(self):
        self.assertEqual(material.SLOTS, SLOTS)
        prepared, pins, projected = material._materials(self.values())
        self.assertEqual(tuple(prepared), tuple(SLOTS))
        self.assertEqual(set(projected), {"persistence", "generationJournal"})
        self.assertEqual(set(projected["persistence"]), {"configuration", "genesis", "journal"})
        self.assertEqual(projected["generationJournal"]["records"], [])
        for purpose, maximum in SLOTS.items():
            self.assertEqual(publication.PROFILES[purpose][2], maximum)
            self.assertEqual(pins[purpose], {"path": "/etc/serverware/native-pilot-inputs/" + purpose + ".json",
                "sha256": sha(prepared[purpose])})
            publication.shape(purpose, prepared[purpose])

    def test_persistence_public_originals_keep_authenticated_grant_commitments(self):
        raw = self.service["grantOriginal"]
        services.checked_result("persistence", self.service["inputOriginal"],
            {"original": raw.decode("ascii"), "sha256": sha(raw)}, **clocks(self.f))
        prepared, _, _ = material._materials(self.values())
        for field, suffix in (("configurationOriginal", "configuration"), ("genesisOriginal", "genesis"), ("journalOriginal", "journal")):
            self.assertEqual(prepared["native-persistence-" + suffix], self.persistence[field].encode("ascii"))
        grant = json.loads(raw)["payload"]
        self.assertEqual(grant["journal"]["genesisSha256"], sha(prepared["native-persistence-genesis"]))
        self.assertEqual(grant["journal"], json.loads(prepared["native-persistence-journal"]))
        changed = json.loads(raw); changed["signature"] = encoded(bytes(64))
        wrong = canonical(changed)
        with self.assertRaises(InvalidSignature):
            services.checked_result("persistence", self.service["inputOriginal"],
                {"original": wrong.decode("ascii"), "sha256": sha(wrong)}, **clocks(self.f))

    def test_projection_copies_generation_original_and_never_creates_records(self):
        values = self.values()
        prepared, _, _ = material._materials(values)
        self.assertEqual(prepared["native-generation-install-genesis"], values["generationInstall"]["genesisOriginal"].encode("ascii"))
        for records in (None, {}, ["{}"], ["invented-record"], True):
            changed = self.values(); changed["generationInstall"]["recordOriginals"] = records
            with self.assertRaises(ValueError): material._materials(changed)

    def test_closed_genesis_and_journal_shapes_reject_versions_history_and_null(self):
        prepared, _, _ = material._materials(self.values())
        for purpose in ("native-persistence-genesis", "native-persistence-journal", "native-generation-install-genesis"):
            raw = prepared[purpose]
            for change in ("extra", "missing", "null", "noncanonical"):
                value = json.loads(raw)
                if change == "extra": value["authorityApproved"] = True
                elif change == "missing": value.pop(next(iter(value)))
                elif change == "null": value[next(iter(value))] = None
                altered = raw + b"\n" if change == "noncanonical" else canonical(value)
                with self.subTest(purpose=purpose, change=change), self.assertRaises(ValueError): publication.shape(purpose, altered)
        for sequence in (True, 1, -1):
            row = json.loads(prepared["native-persistence-journal"]); row["headSequence"] = sequence
            with self.assertRaises(ValueError): material.shape("native-persistence-journal", canonical(row))
        row = json.loads(prepared["native-persistence-journal"]); row["headSha256"] = synthetic("different-head")
        with self.assertRaises(ValueError): material.shape("native-persistence-journal", canonical(row))

    def test_full_native_configuration_not_an_arbitrary_public_document(self):
        raw = self.persistence["configurationOriginal"].encode("ascii")
        self.assertEqual(material.shape("native-persistence-configuration", raw), json.loads(raw))
        for change in ("api", "extra", "scope", "clock", "signature", "key-count"):
            value = json.loads(raw)
            if change == "api": value["apiVersion"] = "serverware.nativeShadowNitroVerifierConfiguration/v1"
            elif change == "extra": value["publicationPath"] = "/etc/arbitrary.json"
            elif change == "scope": value["expectedScope"] = None
            elif change == "clock": value["operation"]["deadlineBoottimeNs"] = value["operation"]["issuedAtBoottimeNs"]
            elif change == "signature": value["authorization"]["signature"] = "not-a-signature"
            else: value["authorityKeys"].pop()
            with self.subTest(change=change), self.assertRaises(ValueError):
                material.shape("native-persistence-configuration", canonical(value))

    def test_bundle_requires_both_complete_authenticated_services_and_fixed_versions(self):
        pins = {role: {"path": "/etc/serverware/native-pilot-inputs/native-launch-" + role + ".json",
            "sha256": synthetic("uninstalled-launch/" + role)} for role in material.ROLES}
        contexts = {"persistence": {name: self.service[name] for name in ("inputOriginal", "grantOriginal")},
            "generationInstall": {"inputOriginal": b"{}", "grantOriginal": b"{}"}}
        with self.assertRaises(ValueError):
            material.build(fragment=POLICY, service_contexts=contexts, endpoint_launches=pins, **clocks(self.f))
        bundle = {"apiVersion": material.API, "serviceContexts": {
            role: {name: raw.decode("ascii") for name, raw in row.items()} for role, row in contexts.items()}, "endpointLaunches": pins}
        for value in ({}, bundle | {"apiVersion": material.API + "-unknown"}, bundle | {"extra": True},
                bundle | {"serviceContexts": {"persistence": bundle["serviceContexts"]["persistence"]}}):
            with self.assertRaises(ValueError): material.prepare_bundle(canonical(value), **clocks(self.f))

    def test_result_projection_preserves_original_deadlines_and_exact_material(self):
        # Only projection is exercised here. checked_result requires the full
        # authenticated two-service bundle; no synthetic owner is introduced.
        _, pins, projected = material._materials(self.values())
        context = {"window": self.f["window"], "pins": pins, "material": projected}
        raw = canonical({"syntheticProjectionOnly": True})
        result = material._result(raw, context)
        self.assertEqual(result, {"apiVersion": "serverware.nativePilotServiceMaterialInstallation/v1",
            "bundleSha256": sha(raw), "startupDeadlineBoottimeNs": self.f["window"]["startupDeadlineBoottimeNs"],
            "lifetimeDeadlineBoottimeNs": self.f["window"]["lifetimeDeadlineBoottimeNs"], "material": projected, "pins": pins})


if __name__ == "__main__":
    unittest.main(verbosity=2)
