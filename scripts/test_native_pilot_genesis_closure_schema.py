#!/usr/bin/env python3
"""Public Closure/v6 grammar controls using explicitly synthetic manifests.

The all-zero signature sentinel is deliberately invalid. No signature, live
window, process/image owner, C9 admission or commissioning is exercised here.
Schema validation cannot establish digest equality or cryptographic authority.
Every referenced schema is loaded from an exact local filename allowlist.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest
from urllib.parse import urldefrag, urljoin

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import test_native_pilot_closure_set as fixtures
import test_native_pilot_genesis_bootstrap_profiles as bootstrap
from catchplate import native_pilot_closure_set as closure

SCHEMAS = ("native-custody-closure.v6.schema.json", "native-publication-genesis-closure-set.v2.schema.json",
    "native-custody-closure.v1.schema.json", "native-custody-closure.v2.schema.json",
    "native-custody-execution-closure-set.v1.schema.json", "policy-shadow-assignment.v1.schema.json",
    "policy-custody-guest-delivery.v1.schema.json")


def reject_external(uri):
    raise AssertionError("Schema reference is not in the fixed local registry: " + uri)


def fixture(role):
    selected = json.loads(closure.set_original(bootstrap.members(), api_version=bootstrap.API))
    manifest = copy.deepcopy(selected["members"][bootstrap.ROLES.index(role)]["manifest"])
    guest = {"configurationSha256": fixtures.synthetic("cold-configuration"),
        "deliverySha256": fixtures.synthetic("cold-delivery"),
        "runtimeConfigurationSha256": (fixtures.synthetic("complete-late-coordinator-runtime")
            if role == bootstrap.ROLES[-1] else manifest["runtimeConfigurationSha256"]),
        "serviceRole": "production-bridge", "uid": 64001, "gid": 64001,
        "bootIdBase64url": "AQEBAQEBAQEBAQEBAQEBAQ", "timeNamespaceDevice": 1, "timeNamespaceInode": 2,
        "issuedAtBoottimeNs": "100", "startupDeadlineBoottimeNs": "200", "lifetimeDeadlineBoottimeNs": "300",
        "invocationId": "1" * 32}
    payload = {"apiVersion": "catchplate.nativeCustodyClosureAssignment/v6",
        "purpose": "shadow-custody-closure-set-member", "profile": "native-publication-genesis-closure-set-v2",
        "assignmentId": fixtures.synthetic("cold-assignment"), "assignmentPayloadSha256": fixtures.synthetic("cold-payload"),
        "assignmentRevision": 1, "manifestSha256": manifest["manifestSha256"], "guest": guest,
        "trustCheckpointId": fixtures.synthetic("checkpoint"), "revocationGeneration": 0,
        "revocationRootSha256": fixtures.synthetic("revocations"), "issuedAtUnixNanos": 1, "expiresAtUnixNanos": 2,
        "signingKeyId": fixtures.synthetic("supervisor-id"), "signingKeySpkiSha256": fixtures.synthetic("supervisor-spki"),
        "guestRole": role, "setRootSha256": selected["setRootSha256"], "seccompSetRootSha256": selected["seccompSetRootSha256"],
        "leafSha256": fixtures.frame(bootstrap.LEAF, [role, manifest])}
    return {"apiVersion": "catchplate.nativeCustodyClosure/v6", "manifest": manifest, "closureSet": selected,
        "authorization": {"payload": payload, "signature": fixtures.INVALID_SIGNATURE_SENTINEL}}


class GenesisClosureSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schemas = {name: json.loads((ROOT / "schemas" / name).read_text()) for name in SCHEMAS}
        for name, value in cls.schemas.items():
            if value["$id"] != "https://catchplate.invalid/schemas/" + name:
                raise AssertionError("Unexpected local schema identifier")
            Draft202012Validator.check_schema(value)
        registry = Registry(retrieve=reject_external).with_resources(
            (value["$id"], Resource.from_contents(value)) for value in cls.schemas.values())
        cls.validator = Draft202012Validator(cls.schemas[SCHEMAS[0]], registry=registry)

    def refuse(self, value):
        self.assertFalse(self.validator.is_valid(value))

    def test_all_three_roles_match_the_explicit_manifest_split(self):
        for role in bootstrap.ROLES:
            with self.subTest(role=role):
                value = fixture(role)
                self.validator.validate(value)
                self.assertEqual(value["authorization"]["signature"], fixtures.INVALID_SIGNATURE_SENTINEL)
                self.assertEqual(value["manifest"]["apiVersion"], "catchplate.nativeCustodyExecutionClosure/v"
                    + ("2" if role == bootstrap.ROLES[-1] else "1"))

    def test_old_closure_assignment_and_set_versions_refuse(self):
        for version in (1, 2, 3, 4, 5):
            value = fixture(bootstrap.ROLES[-1]); value["apiVersion"] = "catchplate.nativeCustodyClosure/v" + str(version)
            self.refuse(value)
            value = fixture(bootstrap.ROLES[-1]); value["authorization"]["payload"]["apiVersion"] = "catchplate.nativeCustodyClosureAssignment/v" + str(version)
            self.refuse(value)
        value = fixture(bootstrap.ROLES[-1]); value["closureSet"]["apiVersion"] = "catchplate.nativePublicationGenesisClosureSet/v1"
        self.refuse(value)

    def test_cross_manifest_versions_and_member_order_refuse(self):
        for index, role in enumerate(bootstrap.ROLES):
            wrong = bootstrap.manifest(role, late=index != 2)
            value = fixture(role); value["manifest"] = wrong; self.refuse(value)
            value = fixture(role); value["closureSet"]["members"][index]["manifest"] = wrong; self.refuse(value)
        value = fixture(bootstrap.ROLES[-1]); value["closureSet"]["members"].reverse(); self.refuse(value)

    def test_closed_roles_profiles_fields_and_signature_grammar(self):
        for field, replacement in (("guestRole", "bridge"), ("profile", "native-publication-genesis-closure-set-v1"),
                ("purpose", "shadow-custody-bootstrap-late-runtime"), ("extra", True)):
            value = fixture(bootstrap.ROLES[-1]); value["authorization"]["payload"][field] = replacement; self.refuse(value)
        for path in ((), ("authorization",), ("authorization", "payload", "guest")):
            value = fixture(bootstrap.ROLES[0]); target = value
            for name in path: target = target[name]
            target["extra"] = True; self.refuse(value)
        value = fixture(bootstrap.ROLES[0]); value["authorization"]["signature"] = "A" * 85; self.refuse(value)

    def test_native_u64_fields_do_not_inherit_old_i64_ceiling(self):
        paths = (("assignmentRevision",), ("revocationGeneration",), ("guest", "timeNamespaceDevice"), ("guest", "timeNamespaceInode"))
        for path in paths:
            value = fixture(bootstrap.ROLES[-1]); target = value["authorization"]["payload"]
            for name in path[:-1]: target = target[name]
            target[path[-1]] = (1 << 64) - 1; self.validator.validate(value)
            target[path[-1]] = 1 << 64; self.refuse(value)
            target[path[-1]] = -1; self.refuse(value)

    def test_all_schema_references_are_fixed_local_resources(self):
        ids = {value["$id"] for value in self.schemas.values()}
        def visit(value, base):
            if isinstance(value, dict):
                if "$ref" in value:
                    self.assertIn(urldefrag(urljoin(base, value["$ref"]))[0], ids)
                for child in value.values(): visit(child, base)
            elif isinstance(value, list):
                for child in value: visit(child, base)
        for value in self.schemas.values(): visit(value, value["$id"])


if __name__ == "__main__":
    unittest.main()
