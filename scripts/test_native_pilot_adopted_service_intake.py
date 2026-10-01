#!/usr/bin/env python3
"""Pure selected reply/pin/material controls, not complete native admission.

All pins and opaque originals below are synthetic grammar data. Positive
controls reach only the real closed shape selectors; full Bundle admission is
tested only for refusal without authentic native service evidence. No owner,
ReceivedGenesisCore, signature validator, resource allocation or installer is
mocked, constructed or executed. The 32 MiB test is a public input size bound,
not proof of a protected file or successful publication.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import native_pilot_service_inputs as intake
from serverware import native_pilot_service_material as material
from serverware import native_pilot_publication as publication
from serverware import native_pilot_publication_profiles as profiles

ENDPOINTS = ("retrieval", "persistence", "trustedTime", "generationInstall", "commitRequest",
    "ingressAdmission", "terminalAppend", "dispatchBarrier", "activeEffectBarrier", "activeEffectCommit")
ADOPTED_ENDPOINTS = ENDPOINTS + ("publicationReconciliation",)
ORDINARY = ("durable-recovery-store", "cleanup-authorization-consumer", "recovery-target-provider",
    "current-signature-authority", "bounded-cleanup-helper")
PUBLICATIONS = (ORDINARY[0], ORDINARY[3])
SPOOL_NATIVE = ("ingress", "ledger", "retrieval", "terminal", "dispatchBarrier", "activeEffectBarrier", "activeEffectCommit")
POLICY = {"apiVersion": "serverware.nativePilotServiceMaterialPolicy/v2", "initialization": "adopted-persistence-and-generation"}
SLOT = "native-persistence-service-input"


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def pin(name):
    return {"path": "/etc/serverware/native-pilot-inputs/" + name + ".json",
        "sha256": "sha256:" + hashlib.sha256(("SYNTHETIC/PIN/" + name).encode("ascii")).hexdigest()}


def pins(prefix, roles):
    return {role: pin(prefix + "-" + role) for role in roles}


def reply(*, adopted=False):
    value = {"ordinaryDeliveries": pins("delivery", ORDINARY), "ordinaryGrants": pins("generation", ORDINARY),
        "dispatchGrants": pins("dispatch", PUBLICATIONS), "dispatchNativeGrant": pin("native-dispatch"),
        "spoolGrants": pins("spool", (ORDINARY[0], ORDINARY[1], ORDINARY[3])),
        "nativeSpoolGrants": pins("native-spool", SPOOL_NATIVE),
        "endpointLaunches": pins("launch", ADOPTED_ENDPOINTS if adopted else ENDPOINTS),
        "persistence": pins("persistence", ("configuration", "genesis", "journal")),
        "generationJournal": {"genesis": pin("generation-genesis"), "records": []}}
    if adopted:
        value.update(publicationGrants=pins("publication", PUBLICATIONS), nativePublicationGrant=pin("native-publication"),
            persistenceServiceInput=pin(SLOT))
    return value


class AdoptedServiceIntakeControls(unittest.TestCase):
    def test_closed_reply_shapes_and_actual_role_rosters(self):
        for adopted, roles in ((False, ENDPOINTS), (True, ADOPTED_ENDPOINTS)):
            value = reply(adopted=adopted); frozen = copy.deepcopy(value)
            self.assertEqual(intake.input_shape(value, adopted=adopted), frozen)
            self.assertEqual(tuple(value["endpointLaunches"]), roles)
        self.assertEqual(intake.ENDPOINT_INPUT_ROLES, ("retrieval", "persistence", "trustedTime"))
        self.assertEqual(intake.ADOPTED_ENDPOINT_INPUT_ROLES, intake.ENDPOINT_INPUT_ROLES + ("publicationReconciliation",))
        self.assertEqual(len(ENDPOINTS), 10); self.assertEqual(len(ADOPTED_ENDPOINTS), 11)

    def test_old_and_adopted_replies_cannot_select_each_other(self):
        with self.assertRaises(ValueError): intake.input_shape(reply(adopted=True))
        with self.assertRaises(ValueError): intake.input_shape(reply(), adopted=True)
        for selected in (0, 1, None, "true"):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                intake.input_shape(reply(adopted=True), adopted=selected)

    def test_adopted_publication_and_persistence_pins_are_mandatory(self):
        for name in ("publicationGrants", "nativePublicationGrant", "persistenceServiceInput"):
            for mutation in ("missing", "null", "extra"):
                value = reply(adopted=True)
                if mutation == "missing": value.pop(name)
                elif mutation == "null": value[name] = None
                else: value[name]["extra"] = pin("unexpected")
                with self.subTest(name=name, mutation=mutation), self.assertRaises(ValueError):
                    intake.input_shape(value, adopted=True)
        for role in PUBLICATIONS:
            value = reply(adopted=True); value["publicationGrants"].pop(role)
            with self.assertRaises(ValueError): intake.input_shape(value, adopted=True)

    def test_wrong_missing_and_extra_pin_members_refuse(self):
        for field in ("ordinaryDeliveries", "ordinaryGrants", "dispatchGrants", "spoolGrants",
                "nativeSpoolGrants", "endpointLaunches", "persistence"):
            for mutation in ("missing", "extra", "digest", "pin-field", "relative"):
                value = reply(adopted=True); group = value[field]; role = next(iter(group))
                if mutation == "missing": group.pop(role)
                elif mutation == "extra": group["wrong-role"] = pin("wrong-role")
                elif mutation == "digest": group[role]["sha256"] = "not-a-sha"
                elif mutation == "relative": group[role]["path"] = "relative.json"
                else: group[role]["approved"] = True
                with self.subTest(field=field, mutation=mutation), self.assertRaises(ValueError):
                    intake.input_shape(value, adopted=True)
        value = reply(adopted=True); value["generationJournal"]["records"] = [None]
        with self.assertRaises(ValueError): intake.input_shape(value, adopted=True)

    def test_material_policy_two_requires_explicit_selected_initialization(self):
        self.assertEqual(material.validate_policy(POLICY, adopted=True), POLICY)
        with self.assertRaises(ValueError): material.validate_policy(POLICY)
        legacy = {"apiVersion": "serverware.nativePilotServiceMaterialPolicy/v1", "initialization": "fresh-persistence-and-generation"}
        self.assertEqual(material.validate_policy(legacy), legacy)
        with self.assertRaises(ValueError): material.validate_policy(legacy, adopted=True)
        for changed in (POLICY | {"initialization": legacy["initialization"]}, POLICY | {"approved": True}):
            with self.assertRaises(ValueError): material.validate_policy(changed, adopted=True)

    def test_bundle_two_is_not_auto_selected_or_admitted_without_evidence(self):
        value = {"apiVersion": material.ADOPTED_API,
            "serviceContexts": {role: {"inputOriginal": "{}", "grantOriginal": "{}"} for role in material.ROLES},
            "endpointLaunches": pins("launch", material.ROLES)}
        clocks = dict(boot=("synthetic", 1, 2), now_boottime_ns=1000, now_unix_ns=1000)
        with self.assertRaises(ValueError): material.prepare_bundle(canonical(value), **clocks)
        # Selecting v2 is necessary, never sufficient. No authentic full
        # adoption transcript is supplied or fabricated in this test.
        value["serviceContexts"]["persistence"]["inputOriginal"] = canonical({
            "apiVersion": material.adopted_services.INPUT_API, "operation": "persistence"}).decode("ascii")
        with self.assertRaises(ValueError): material.prepare_bundle(canonical(value), adopted=True, **clocks)
        value["apiVersion"] = material.API
        with self.assertRaises(ValueError): material.prepare_bundle(canonical(value), adopted=True, **clocks)

    def test_new_public_slot_has_exact_destination_and32mib_cap(self):
        self.assertNotIn(SLOT, material.SLOTS)
        self.assertEqual(material.ADOPTED_SLOTS, material.SLOTS | {SLOT: 32 * 1024 * 1024})
        self.assertEqual(profiles.PROFILES[SLOT], ("service-material", "persistence", 32 * 1024 * 1024))
        self.assertEqual(publication.DESTINATIONS[SLOT], "/etc/serverware/native-pilot-inputs/" + SLOT + ".json")
        # Only outer grammar is claimed. Null nested originals deliberately
        # cannot authenticate or initialize a real Persistence owner.
        fields = material.adopted_services.COMMON + material.adopted_services.EXTRA["persistence"]
        value = {name: None for name in fields}
        value.update(apiVersion=material.adopted_services.INPUT_API, operation="persistence")
        self.assertEqual(material.shape(SLOT, canonical(value)), value)
        for change in ({"apiVersion": "serverware.nativePilotNativeServiceAuthorityInput/v1"},
                {"operation": "retrieval"}, {"unsignedApproval": True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                material.shape(SLOT, canonical(value | change))
        with self.assertRaises(ValueError): material.shape(SLOT, b" " * (32 * 1024 * 1024 + 1))


if __name__ == "__main__": unittest.main()
