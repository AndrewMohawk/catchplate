#!/usr/bin/env python3
"""Public cold-binding controls with deterministic synthetic signatures only.

No signer entrypoint, protected approval, process observation, guest, provisioned
key or native admission is exercised. The reused assignment's unrelated hot
fleet/policy fields are grammar fixtures, not an operational assignment proof.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from catchplate import custody_generation_grants as codec
from catchplate import native_pilot_closure_set as closure
from catchplate import native_pilot_publication_cold_binding as cold
from test_native_pilot_closure_set import frame, sha, synthetic, members_fixture
from test_native_pilot_generation_scope import fixture as generation_fixture, key_fixture, encoded, trust_key, NOW
from test_native_pilot_genesis_bootstrap_profiles import members


def resign(value):
    envelope = json.loads(value["assignmentOriginal"])
    envelope["payloadSha256"] = sha(codec.canonical(envelope["payload"]))
    preimage = (b"catchplate.signedEnvelope/v1\0catchplate.policyShadowAssignment/v2"
        b"\0catchplate.canonicalJson/ascii-integer-v1\0" + codec.canonical(envelope["payload"]))
    envelope["signature"] = encoded(key_fixture("assignment")[0].sign(preimage))
    value["assignmentOriginal"] = codec.canonical(envelope).decode("ascii")


def select_set(value, raw):
    selected = json.loads(raw)
    envelope = json.loads(value["assignmentOriginal"])
    payload = envelope["payload"]
    payload["nativeClosureSet"] = {name: selected[name] for name in ("setRootSha256", "seccompSetRootSha256")}
    manifest = selected["members"][-1]["manifest"]
    payload["custodyAuthority"].update(executionClosureManifestSha256=manifest["manifestSha256"],
        structurallyVerifiedSeccompPolicySha256=manifest["seccompPolicy"]["structurallyVerifiedPolicySha256"])
    value["assignmentOriginal"] = codec.canonical(envelope).decode("ascii")
    value["closureSetOriginal"] = raw.decode("ascii")
    resign(value)


def fixture():
    _, source, _ = generation_fixture()
    originals = source["recipe_originals"]
    value = {"apiVersion": cold.API, "trustOriginal": originals["trustOriginal"],
        "trustSha256": originals["trustSha256"], "assignmentOriginal": originals["assignmentOriginal"],
        "closureSetOriginal": "", "commissioningIdSha256": synthetic("COLD COMMISSIONING TEST ONLY"),
        "initialPublicationRevision": 1, "window": {"bootIdBase64url": encoded(b"synthetic-boot16"),
            "timeNamespaceDevice": 4, "timeNamespaceInode": 5, "issuedAtBoottimeNanos": 1000,
            "expiresAtBoottimeNanos": 9_000_000_000, "issuedAtUnixNanos": NOW - 1_000_000_000,
            "expiresAtUnixNanos": NOW + 20_000_000_000}}
    select_set(value, closure.set_original(members(), api_version=closure.GENESIS_BOOTSTRAP_API))
    return value


def prepare(value, **changes):
    raw = codec.canonical(value)
    clocks = {"boot": (value["window"]["bootIdBase64url"], value["window"]["timeNamespaceDevice"],
        value["window"]["timeNamespaceInode"]), "now_boottime_ns": 2000, "now_unix_ns": NOW}
    clocks.update(changes)
    return cold.prepare(input_original=raw, expected_input_sha256=sha(raw), **clocks)


def mutate_trust(value, callback):
    trust = json.loads(value["trustOriginal"]); callback(trust)
    raw = codec.canonical(trust)
    value["trustOriginal"], value["trustSha256"] = raw.decode("ascii"), sha(raw)


class ColdBindingTests(unittest.TestCase):
    def setUp(self):
        self.value = fixture()

    def refused(self, value, **clocks):
        with self.assertRaises((ValueError, InvalidSignature, TypeError, KeyError)):
            prepare(value, **clocks)

    def test_signed_assignment_derives_exact_native_scope_without_hot_driver(self):
        raw = prepare(self.value); result = cold.result_document(raw)
        binding = json.loads(result["configurationBindingOriginal"])
        proof = json.loads(result["proofScopeOriginal"])
        genesis = json.loads(result["genesisScopeOriginal"])
        self.assertEqual(result["inputSha256"], sha(codec.canonical(self.value)))
        self.assertEqual(result["configurationBindingSha256"], frame(cold.BINDING_API, binding))
        self.assertNotEqual(result["configurationBindingSha256"], frame("catchplate.policyShadowProductionCustodyConfiguration/v2", binding))
        self.assertEqual(proof["binding_sha256"], frame("catchplate.policyShadowProductionCustodyProofScope/v2",
            [proof[name] for name in cold.retrieval.SCOPE_VALUES + cold.retrieval.SCOPE_SET_VALUES]))
        for field, role in (("store_response_authority", "custody-store-response"),
                            ("retrieval_response_authority", "custody-retrieval-response")):
            selected = next(key for key in binding["custodyKeys"] if key["role"] == role)
            self.assertEqual(proof[field]["key_id"], selected["keyId"])
            self.assertEqual(proof[field]["key_material_sha256"], selected["keyMaterialSha256"])
        self.assertEqual(genesis["proofScopeOriginal"], result["proofScopeOriginal"])
        self.assertEqual(genesis["productionConfigurationBindingSha256"], result["configurationBindingSha256"])
        self.assertEqual(genesis["expiresAtBoottimeNanos"], self.value["window"]["expiresAtBoottimeNanos"])
        self.assertFalse({"kernelRetainedDriverIdentitySha256", "operationCoverageRootSha256", "production", "guest"} & set(binding))
        self.assertEqual(binding["purpose"], "cold-publication-genesis")

    def test_complete_input_pin_closed_canonical_and_bounded(self):
        raw = codec.canonical(self.value)
        with self.assertRaises(ValueError):
            cold.prepare(raw, expected_input_sha256=synthetic("not-approved-input"),
                boot=(self.value["window"]["bootIdBase64url"], 4, 5), now_boottime_ns=2000, now_unix_ns=NOW)
        for changed in (dict(self.value, futureDriver={}), dict(self.value, apiVersion="catchplate.nativePilotMeasuredConfigurationRecipe/v2")):
            self.refused(changed)
        for bad in (raw + b"\n", b'{"apiVersion":"ignored",' + raw[1:], b" " * (cold.MAX_INPUT + 1)):
            with self.assertRaises(ValueError):
                cold.input_document(bad)
        self.assertEqual(cold.MAX_INPUT, codec.MAX_BYTES)

    def test_signed_assignment_tamper_wrong_key_domain_and_key_material_refuse(self):
        for mutate in (
            lambda e: e.update(signature=encoded(b"x" * 64)),
            lambda e: e.update(signatureDomain="catchplate.policyShadowAssignment/v1"),
            lambda e: e.update(signingKeyId=synthetic("unapproved-assignment-key")),
            lambda e: e["payload"].update(assignmentRevision=2),
        ):
            changed = copy.deepcopy(self.value); envelope = json.loads(changed["assignmentOriginal"])
            mutate(envelope); changed["assignmentOriginal"] = codec.canonical(envelope).decode("ascii")
            self.refused(changed)
        changed = copy.deepcopy(self.value)
        mutate_trust(changed, lambda trust: trust["roleKeys"][0].update(key=trust_key(key_fixture("different-role")[1])))
        self.refused(changed)
        changed = copy.deepcopy(self.value)
        mutate_trust(changed, lambda trust: trust["roleKeys"].append(copy.deepcopy(trust["roleKeys"][0])))
        self.refused(changed)
        changed = copy.deepcopy(self.value)
        mutate_trust(changed, lambda trust: trust["roleKeys"].append({"role": "independent-extra-public-key",
            "key": trust_key(key_fixture("extra-trust-key")[1])}))
        cold.result_document(prepare(changed))

    def test_only_new_cold_set_and_exact_coordinator_anchor_are_selected(self):
        old_members = members()
        old_members[-1]["manifest"] = copy.deepcopy(old_members[0]["manifest"])
        for raw in (closure.set_original(old_members, api_version=closure.GENESIS_API),
                    closure.set_original(members_fixture())):
            changed = copy.deepcopy(self.value); select_set(changed, raw); self.refused(changed)
        changed = copy.deepcopy(self.value); envelope = json.loads(changed["assignmentOriginal"])
        envelope["payload"]["custodyAuthority"]["executionClosureManifestSha256"] = synthetic("wrong-anchor")
        changed["assignmentOriginal"] = codec.canonical(envelope).decode("ascii"); resign(changed)
        self.refused(changed)
        changed = copy.deepcopy(self.value); envelope = json.loads(changed["assignmentOriginal"])
        envelope["payload"]["nativeClosureSet"]["seccompSetRootSha256"] = synthetic("wrong-root")
        changed["assignmentOriginal"] = codec.canonical(envelope).decode("ascii"); resign(changed)
        self.refused(changed)

    def test_original_intervals_current_boot_and_no_renewal(self):
        w = self.value["window"]
        for clocks in ({"now_boottime_ns": w["issuedAtBoottimeNanos"] - 1},
                {"now_boottime_ns": w["expiresAtBoottimeNanos"]}, {"now_unix_ns": w["expiresAtUnixNanos"]},
                {"boot": (encoded(b"x" * 16), 4, 5)}, {"boot": (w["bootIdBase64url"], 4, 6)}):
            self.refused(self.value, **clocks)
        for section in ("assignmentKey", "timeKey", "roleKeys"):
            changed = copy.deepcopy(self.value)
            def shorten(trust):
                key = trust[section][0]["key"] if section == "roleKeys" else trust[section]
                key["notAfterUnixNanos"] = NOW + 1_000_000_000
            mutate_trust(changed, shorten); self.refused(changed)
        changed = copy.deepcopy(self.value)
        mutate_trust(changed, lambda trust: trust["checkpoint"].update(asOfUnixNanos=NOW - cold.MAX_AGE + 1))
        self.refused(changed)
        changed = copy.deepcopy(self.value)
        changed["window"]["issuedAtUnixNanos"] = NOW - 11_000_000_000
        self.refused(changed)
        self.assertEqual(json.loads(prepare(self.value))["deadlineBoottimeNs"], str(w["expiresAtBoottimeNanos"]))

    def test_full_u64_scope_revision_namespace_and_originals(self):
        value = copy.deepcopy(self.value); high = (1 << 63) + 17
        value["initialPublicationRevision"] = high
        value["window"].update(timeNamespaceDevice=high, timeNamespaceInode=high + 1,
            issuedAtBoottimeNanos=high + 2, expiresAtBoottimeNanos=high + 1000)
        envelope = json.loads(value["assignmentOriginal"]); envelope["payload"]["assignmentRevision"] = high
        value["assignmentOriginal"] = codec.canonical(envelope).decode("ascii"); resign(value)
        mutate_trust(value, lambda trust: trust["checkpoint"].update(revocationGeneration=high))
        result = cold.result_document(prepare(value, now_boottime_ns=high + 3))
        self.assertEqual(json.loads(result["proofScopeOriginal"])["assignment_revision"], high)
        self.assertEqual(json.loads(result["genesisScopeOriginal"])["initialPublicationRevision"], high)
        self.assertEqual(result["deadlineBoottimeNs"], str(high + 1000))
        for name in ("timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNanos", "expiresAtBoottimeNanos"):
            changed = copy.deepcopy(self.value); changed["window"][name] = True; self.refused(changed)

    def test_output_exact_proof_key_scope_and_window_associations(self):
        result = json.loads(prepare(self.value))
        for name, replacement in (("configurationBindingSha256", synthetic("changed-binding")),
                ("inputSha256", synthetic("changed-input")), ("deadlineBoottimeNs", "9000000001"),
                ("expiresAtUnixNanos", NOW + 30_000_000_000)):
            changed = copy.deepcopy(result); changed[name] = replacement
            with self.assertRaises(ValueError):
                cold.result_document(codec.canonical(changed))
        changed = copy.deepcopy(result); proof = json.loads(changed["proofScopeOriginal"])
        proof["store_response_authority"]["key_id"] = synthetic("changed-proof-key")
        changed["proofScopeOriginal"] = codec.canonical(proof).decode("ascii")
        with self.assertRaises(ValueError):
            cold.result_document(codec.canonical(changed))
        changed = copy.deepcopy(result); scope = json.loads(changed["genesisScopeOriginal"])
        scope["commissioningIdSha256"] = synthetic("changed-commissioning")
        changed["genesisScopeOriginal"] = codec.canonical(scope).decode("ascii")
        with self.assertRaises(ValueError):
            cold.result_document(codec.canonical(changed))

    def test_schema_closed_input_and_u64_window(self):
        from jsonschema import Draft202012Validator
        schema = json.loads((ROOT / "schemas/native-pilot-publication-cold-binding-input.v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema); validator = Draft202012Validator(schema)
        validator.validate(self.value)
        high = copy.deepcopy(self.value); high["window"]["timeNamespaceDevice"] = (1 << 64) - 1
        validator.validate(high)
        for changed in (dict(self.value, apiVersion="catchplate.nativePilotPublicationColdBindingInput/v2"),
                dict(self.value, driverIdentity={}), dict(self.value, initialPublicationRevision=True)):
            self.assertTrue(list(validator.iter_errors(changed)))


if __name__ == "__main__":
    unittest.main()
