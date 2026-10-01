#!/usr/bin/env python3
"""Synthetic static bootstrap-profile controls, not native commissioning.

Image/runtime/provenance hashes are labelled synthetic. Assignment envelopes
reuse the existing INVALID_SIGNATURE_SENTINEL solely for public root/anchor
association; no signature, actual guest, measurement or approval is claimed.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "authority"))

import prepare_native_pilot_closure_set as preparation
import test_native_pilot_closure_set as fixtures
from serverware import native_pilot_assignment as assignment
from serverware import native_pilot_closure_set as closure

API = "serverware.nativePublicationGenesisClosureSet/v2"
ROLES = ("publicationGenesisRetrieval", "publicationGenesis", "publicationGenesisCoordinator")
LEAF = "serverware.nativePublicationGenesisClosureSetLeaf/v2"
ROOT_DOMAIN = "serverware.nativePublicationGenesisClosureSetRoot/v2"
SECCOMP = "serverware.nativePublicationGenesisSeccompSetRoot/v2"
PREPARATION = "serverware.nativePilotClosureSetPreparation/v3"
AUTHORITY_INPUT = "serverware.nativePilotAssignmentAuthorityInput/v3"


def manifest(role, *, late=False):
    value = fixtures.manifest_fixture(role)
    if late:
        value.update(apiVersion="serverware.nativeCustodyExecutionClosure/v2",
            profile="measured-bootstrap-late-runtime-static-amd64-v1")
        value["manifestSha256"] = fixtures.frame(value["apiVersion"],
            [value[name] for name in fixtures.MANIFEST_FIELDS[:-1]])
    return value


def members():
    return [{"role": role, "manifest": manifest(role, late=role == ROLES[-1])} for role in ROLES]


def authority_input(value, raw):
    envelope = fixtures.assignment_fixture(value)
    return {"apiVersion": AUTHORITY_INPUT, "setApiVersion": API,
        "trustOriginal": "{}", "trustSha256": fixtures.sha(b"{}"),
        "payloadOriginal": fixtures.canonical(envelope["payload"]).decode("ascii"),
        "closureSetOriginal": raw.decode("ascii")}


class GenesisBootstrapProfileTests(unittest.TestCase):
    def setUp(self):
        self.members = members()
        self.raw = closure.set_original(self.members, api_version=API)
        self.value = closure.validate(self.raw, api_version=API)

    def test_exact_three_roles_manifest_split_and_independent_v2_hashes(self):
        self.assertEqual(closure.GENESIS_BOOTSTRAP_API, API)
        self.assertEqual(closure.GENESIS_ROLES, ROLES)
        self.assertEqual(tuple(row["role"] for row in self.value["members"]), ROLES)
        self.assertEqual([row["manifest"]["apiVersion"] for row in self.members],
            ["serverware.nativeCustodyExecutionClosure/v1"] * 2 + ["serverware.nativeCustodyExecutionClosure/v2"])
        leaves = [fixtures.frame(LEAF, [row["role"], row["manifest"]]) for row in self.members]
        policies = [[row["role"], row["manifest"]["seccompPolicy"]["structurallyVerifiedPolicySha256"]]
            for row in self.members]
        self.assertEqual(self.value["setRootSha256"], fixtures.frame(ROOT_DOMAIN, leaves))
        self.assertEqual(self.value["seccompSetRootSha256"], fixtures.frame(SECCOMP, policies))
        for role, leaf in zip(ROLES, leaves, strict=True):
            self.assertEqual(closure.leaf_binding(self.value, role, api_version=API)["leafSha256"], leaf)
        self.assertEqual(closure.require_binding(self.raw, api_version=API,
            expected_set_root=self.value["setRootSha256"],
            expected_seccomp_set_root=self.value["seccompSetRootSha256"]), self.value)

    def test_wrong_manifest_profile_and_inventory_refuse(self):
        cases = []
        for index in range(3):
            changed = copy.deepcopy(self.members)
            changed[index]["manifest"] = manifest(ROLES[index], late=index != 2)
            cases.append(changed)
        changed = copy.deepcopy(self.members)
        changed[-1]["manifest"]["profile"] = "sealed-memfd-squashfs-static-amd64-v1"
        changed[-1]["manifest"]["manifestSha256"] = fixtures.frame(changed[-1]["manifest"]["apiVersion"],
            [changed[-1]["manifest"][name] for name in fixtures.MANIFEST_FIELDS[:-1]])
        cases.extend((changed, self.members[:-1], self.members + [self.members[0]],
            [self.members[1], self.members[0], self.members[2]],
            [self.members[0], self.members[0], self.members[2]]))
        for number, value in enumerate(cases):
            with self.subTest(case=number), self.assertRaises(ValueError):
                closure.set_original(value, api_version=API)
        changed = copy.deepcopy(self.value)
        changed["members"][-1]["manifest"]["runtimeConfigurationSha256"] = fixtures.synthetic("not measured bootstrap")
        with self.assertRaises(ValueError):
            closure.validate(fixtures.canonical(changed), api_version=API)

    def test_old_profiles_and_default_remain_closed_and_unchanged(self):
        for api, roles in ((closure.API, closure.ROLES), (closure.GENESIS_API, ROLES),
                (closure.PUBLICATION_API, closure.PUBLICATION_ROLES)):
            old_members = [{"role": role, "manifest": fixtures.manifest_fixture(role)} for role in roles]
            old_raw = closure.set_original(old_members, api_version=api)
            self.assertEqual(closure.validate(old_raw, api_version=api)["members"], old_members)
            with self.subTest(old=api), self.assertRaises(ValueError):
                closure.validate(self.raw, api_version=api)
            with self.subTest(new=api), self.assertRaises(ValueError):
                closure.validate(old_raw, api_version=API)
        with self.assertRaises(ValueError):
            closure.validate(self.raw)
        old = closure.validate(closure.set_original([
            {"role": role, "manifest": fixtures.manifest_fixture(role)} for role in ROLES],
            api_version=closure.GENESIS_API), api_version=closure.GENESIS_API)
        # Same seccomp rows still have different explicitly selected domains.
        self.assertNotEqual(old["seccompSetRootSha256"], self.value["seccompSetRootSha256"])
        changed = dict(self.value, seccompSetRootSha256=old["seccompSetRootSha256"])
        with self.assertRaises(ValueError):
            closure.validate(fixtures.canonical(changed), api_version=API)

    def test_preparation_v3_selects_only_new_profile_and_literal_pin(self):
        value = {"apiVersion": PREPARATION, "setApiVersion": API, "members": self.members}
        raw = fixtures.canonical(value)
        self.assertEqual(preparation.prepare(raw, fixtures.sha(raw)), self.raw)
        cases = [dict(value, apiVersion=preparation.SUCCESSOR_INPUT_API),
            dict(value, apiVersion=preparation.INPUT_API), dict(value, lateRuntimeOriginal="{}"),
            {key: item for key, item in value.items() if key != "setApiVersion"}]
        cases += [dict(value, setApiVersion=api) for api in
            (closure.API, closure.GENESIS_API, closure.PUBLICATION_API, None, "unknown")]
        for case in cases:
            changed = fixtures.canonical(case)
            with self.subTest(case=case.get("setApiVersion")), self.assertRaises(ValueError):
                preparation.prepare(changed, fixtures.sha(changed))
        for changed in (raw + b"\n", raw.replace(b'"setApiVersion":', b'"setApiVersion":null,"setApiVersion":', 1)):
            with self.assertRaises(ValueError):
                preparation.prepare(changed, fixtures.sha(changed))
        with self.assertRaises(ValueError):
            preparation.prepare(raw, fixtures.synthetic("unapproved input pin"))

    def test_assignment_input_v3_closed_selection_before_key_use(self):
        value = authority_input(self.value, self.raw)
        self.assertEqual(assignment.input_document(fixtures.canonical(value)), (value, API))
        cases = [dict(value, apiVersion="serverware.nativePilotAssignmentAuthorityInput/v" + str(version))
            for version in (1, 2, 4)]
        cases += [dict(value, setApiVersion=api) for api in
            (closure.API, closure.GENESIS_API, closure.PUBLICATION_API, None)]
        cases += [dict(value, actualGuest={}), {key: item for key, item in value.items() if key != "setApiVersion"}]
        for case in cases:
            with self.subTest(api=case["apiVersion"]), self.assertRaises(ValueError):
                assignment.input_document(fixtures.canonical(case))
        with self.assertRaises(ValueError):
            assignment.input_document(fixtures.canonical(value) + b"\n")

    def test_assignment_joins_exact_coordinator_anchor_and_all_members(self):
        envelope = fixtures.assignment_fixture(self.value)
        for role in ROLES:
            self.assertEqual(assignment.closure_binding(envelope, self.raw, role, set_api_version=API),
                closure.leaf_binding(self.value, role, api_version=API))
        with self.assertRaises(ValueError):
            assignment.closure_binding(envelope, self.raw, ROLES[-1])
        with self.assertRaises(ValueError):
            assignment.closure_binding(envelope, self.raw, ROLES[-1], set_api_version=closure.GENESIS_API)
        for field in ("executionClosureManifestSha256", "structurallyVerifiedSeccompPolicySha256"):
            changed = copy.deepcopy(envelope)
            changed["payload"]["custodyAuthority"][field] = fixtures.synthetic("wrong " + field)
            fixtures.rehash_payload(changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                assignment.closure_binding(changed, self.raw, ROLES[-1], set_api_version=API)
        changed = copy.deepcopy(envelope)
        changed["payload"]["custodyAuthority"]["executionClosureManifestSha256"] = self.members[0]["manifest"]["manifestSha256"]
        fixtures.rehash_payload(changed)
        with self.assertRaises(ValueError):
            assignment.closure_binding(changed, self.raw, ROLES[-1], set_api_version=API)

    def test_assignment_both_roots_are_exact_even_after_payload_rehash(self):
        envelope = fixtures.assignment_fixture(self.value)
        for field in ("setRootSha256", "seccompSetRootSha256"):
            changed = copy.deepcopy(envelope)
            changed["payload"]["nativeClosureSet"][field] = fixtures.synthetic("different approved " + field)
            fixtures.rehash_payload(changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                assignment.closure_binding(changed, self.raw, ROLES[-1], set_api_version=API)
        for field in ("guest", "assignmentPayloadSha256", "signature"):
            changed = dict(self.value, **{field: fixtures.synthetic("forbidden static field")})
            with self.subTest(field=field), self.assertRaises(ValueError):
                closure.validate(fixtures.canonical(changed), api_version=API)

    def test_schemas_require_new_profile_and_exact_manifest_split(self):
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        names = ("native-custody-closure.v1.schema.json", "native-custody-closure.v2.schema.json",
            "native-custody-execution-closure-set.v1.schema.json", "native-custody-execution-closure-set.v2.schema.json",
            "native-publication-genesis-closure-set.v1.schema.json", "native-publication-genesis-closure-set.v2.schema.json",
            "native-pilot-closure-set-preparation.v2.schema.json", "native-pilot-closure-set-preparation.v3.schema.json",
            "native-pilot-assignment-authority-input.v2.schema.json", "native-pilot-assignment-authority-input.v3.schema.json")
        schemas = {name: json.loads((ROOT / "schemas" / name).read_text()) for name in names}
        registry = Registry().with_resources((value["$id"], Resource.from_contents(value)) for value in schemas.values())
        for value in schemas.values():
            Draft202012Validator.check_schema(value)
        prepared = {"apiVersion": PREPARATION, "setApiVersion": API, "members": self.members}
        values = (("native-publication-genesis-closure-set", self.value),
            ("native-pilot-closure-set-preparation", prepared),
            ("native-pilot-assignment-authority-input", authority_input(self.value, self.raw)))
        for name, value in values:
            version = 2 if name == "native-publication-genesis-closure-set" else 3
            validator = Draft202012Validator(schemas[name + ".v" + str(version) + ".schema.json"], registry=registry)
            validator.validate(value)
            prior = Draft202012Validator(schemas[name + ".v" + str(version - 1) + ".schema.json"], registry=registry)
            self.assertTrue(list(prior.iter_errors(value)))
            changed = copy.deepcopy(value)
            changed["apiVersion"] = changed["apiVersion"].removesuffix(str(version)) + str(version - 1)
            self.assertTrue(list(validator.iter_errors(changed)))
            if "members" in value:
                changed = copy.deepcopy(value)
                changed["members"][-1]["manifest"] = manifest(ROLES[-1])
                self.assertTrue(list(validator.iter_errors(changed)))
                changed = copy.deepcopy(value)
                changed["members"][0]["manifest"] = manifest(ROLES[0], late=True)
                self.assertTrue(list(validator.iter_errors(changed)))
            else:
                self.assertTrue(list(validator.iter_errors(dict(value, setApiVersion=closure.GENESIS_API))))


if __name__ == "__main__":
    unittest.main()
