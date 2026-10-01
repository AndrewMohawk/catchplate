#!/usr/bin/env python3
"""Bounded public constructed projections, not a full constructed transcript.

Real deterministic test signatures authenticate the adopted bridge pair/C9 and
bootstrap. Runtime14's nested receipts and the exported-evidence placeholders
remain explicitly synthetic data. No owner, native evidence, installed launch,
constructed admission or successful complete compose() is fabricated here.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from serverware import native_pilot_adopted_constructed_inputs as inputs
from test_native_pilot_adopted_bridge_keys import fixture as bridge_fixture, closure_input, closure_result
from test_native_pilot_bridge_authorizations import pair, clocks
from test_native_pilot_continuation_profile import policy_fixture, bootstrap_fixture
from test_native_pilot_generation_scope import key_fixture, encoded
from test_native_pilot_closure_set import canonical, sha, synthetic


def record(raw, output):
    return {"input": raw, "result": {"original": output.decode("ascii"), "sha256": sha(output)}}


def fixture():
    value, guest, manifest = bridge_fixture()
    originals = pair(value, guest, manifest)
    prior = {}
    for name, first, second in (("native-role-keys-bridge", "roleKeyInputOriginal", "roleKeyOriginal"),
            ("native-key-admission-bridge", "admissionInputOriginal", "admissionOriginal")):
        prior[name] = record(originals[first].encode("ascii"), originals[second].encode("ascii"))
    prior["native-delivery-bridge"] = record(value["deliveryInputOriginal"].encode("ascii"),
        value["deliveryOriginal"].encode("ascii"))
    raw, result, _ = bootstrap_fixture()
    prior["driver-bootstrap"] = {"input": raw, "result": result}
    return dict(value=value, guest=guest, manifest=manifest, originals=originals,
        fragment=policy_fixture(value), prior=prior, clocks=clocks(),
        observed={"recipeOriginals": value["recipeOriginals"], "measuredConfiguration": value["measured"]},
        bootstrap=inputs._bootstrap(prior))


class AdoptedConstructedCandidateControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.case = fixture()

    def verifier(self, *, fragment=None, prior=None, observed=None, **changes):
        f = self.case
        return inputs._verifier(f["fragment"] if fragment is None else fragment,
            f["prior"] if prior is None else prior, f["observed"] if observed is None else observed,
            f["bootstrap"], {**f["clocks"], **changes})

    def test_only_actual_constructed_job_and_explicit_continuation_policy(self):
        selected = inputs.profile.BY_NAME["driver-constructed"][1]
        self.assertEqual(inputs.selection_fields(selected), ("continuationPolicy",))
        for name in ("driver-bootstrap", "cohort-release", "native-role-keys-bridge"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                inputs.selection_fields(inputs.profile.BY_NAME[name][1])
        with self.assertRaises(ValueError): inputs.selection_fields({"name": "driver-constructed"})
        policy = inputs.continuation.validate_policy(self.case["fragment"])
        self.assertEqual(policy, self.case["fragment"])
        with self.assertRaises(ValueError):
            inputs.continuation.validate_policy(policy | {"verifierConfigurationOriginal": "{}"})

    def test_verifier_authenticates_adopted_pair_and_preserves_original_window(self):
        raw, pair_context = self.verifier()
        value = json.loads(raw)
        self.assertEqual(pair_context, self.case["originals"])
        self.assertEqual(value["apiVersion"], "serverware.nativeShadowNitroVerifierConfiguration/v3")
        self.assertEqual(value["expectedScope"]["guest"], self.case["guest"])
        self.assertEqual(value["operation"]["deadlineBoottimeNs"], self.case["guest"]["startupDeadlineBoottimeNs"])
        self.assertEqual(value["authorityKeys"][-1]["role"], "custody-supervisor-capability")
        self.assertEqual(value["expectedScope"]["productionConfigurationBindingSha256"],
            self.case["value"]["measured"]["configurationBindingSha256"])

    def test_assignment_pem_requires_current_pinned_trust_key(self):
        fragment = copy.deepcopy(self.case["fragment"])
        raw = key_fixture("unrelated-assignment-public-key")[0].public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        fragment.update(assignmentPublicKeyOriginal=raw.decode("ascii"), assignmentPublicKeySha256=sha(raw))
        inputs.continuation.validate_policy(fragment)
        with self.assertRaises(ValueError): self.verifier(fragment=fragment)
        fragment = copy.deepcopy(self.case["fragment"])
        fragment["assignmentPublicKeySha256"] = synthetic("wrong-public-key-pin")
        with self.assertRaises(ValueError): self.verifier(fragment=fragment)

    def test_original_recipe_measurement_and_c9_are_literal_predecessors(self):
        for group, field in (("recipeOriginals", "trustOriginal"), ("measuredConfiguration", "configurationBindingSha256")):
            observed = copy.deepcopy(self.case["observed"]); observed[group][field] = synthetic("other-original")
            with self.subTest(field=field), self.assertRaises(ValueError): self.verifier(observed=observed)
        prior = copy.deepcopy(self.case["prior"])
        source = json.loads(prior["native-delivery-bridge"]["input"])
        source["runtimeOriginal"] = "{}"
        prior["native-delivery-bridge"]["input"] = canonical(source)
        with self.assertRaises(ValueError): self.verifier(prior=prior)

    def test_legacy_selection_signature_and_original_clock_refusals(self):
        for name in ("native-role-keys-bridge", "native-key-admission-bridge"):
            prior = copy.deepcopy(self.case["prior"])
            source = json.loads(prior[name]["input"]); source["apiVersion"] = inputs.keys.API
            prior[name]["input"] = canonical(source)
            with self.subTest(name=name), self.assertRaises(ValueError): self.verifier(prior=prior)
        prior = copy.deepcopy(self.case["prior"])
        signed = json.loads(prior["native-key-admission-bridge"]["result"]["original"])
        signed["signature"] = encoded(bytes(64))
        prior["native-key-admission-bridge"] = record(prior["native-key-admission-bridge"]["input"], canonical(signed))
        with self.assertRaises(InvalidSignature): self.verifier(prior=prior)
        for change in ({"now_boottime_ns": int(self.case["guest"]["startupDeadlineBoottimeNs"])},
                {"now_unix_ns": self.case["value"]["policy"]["expiresAtUnixNanos"]}):
            with self.subTest(change=change), self.assertRaises(ValueError): self.verifier(**change)

    def test_guest_ids_cannot_be_used_for_independent_verifier(self):
        for name in ("uid", "gid"):
            fragment = copy.deepcopy(self.case["fragment"])
            fragment["verifierSettings"][name] = self.case["guest"][name]
            with self.subTest(name=name), self.assertRaises(ValueError): self.verifier(fragment=fragment)

    def test_exported_literal_association_is_exact_not_evidence_admission(self):
        f = self.case
        closure = closure_result(closure_input(f["value"], f["guest"], f["manifest"]))["original"]
        components = {"closure": closure, "keys": canonical({"apiVersion": "serverware.nativeShadowRoleKeys/v2",
            "authorization": json.loads(f["originals"]["roleKeyOriginal"])}).decode("ascii"),
            "admission": f["originals"]["admissionOriginal"]}
        scope_raw = b'{"synthetic":"scope-not-native-admission"}'
        scope_input = {"publicBundleOriginal": '{"synthetic":"phase-bundle"}',
            "observationOriginal": json.loads(f["value"]["deliveryInputOriginal"])["observationOriginal"]}
        bootstrap_raw = f["prior"]["driver-bootstrap"]["result"]["original"].encode("ascii")
        exported = {"apiVersion": "serverware.nativeShadowDriverPublicAdmission/v1",
            "bootstrapObservationOriginal": scope_input["observationOriginal"], "phaseScopeOriginal": scope_raw.decode("ascii"),
            "phaseBundleOriginal": scope_input["publicBundleOriginal"], "assignmentOriginal": f["value"]["recipeOriginals"]["assignmentOriginal"],
            "closureOriginal": components["closure"], "keyConfigurationOriginal": components["keys"],
            "admissionAuthorizationOriginal": components["admission"], "evidenceOriginal": '{"synthetic":"no-nitro-evidence"}',
            "combinedResultOriginal": '{"synthetic":"no-native-result"}'}
        observed = {"payloadOriginal": "{}", "censusOriginal": "{}", "publicAdmissionOriginal": canonical(exported).decode("ascii"),
            "bootstrapAdmissionOriginal": bootstrap_raw.decode("ascii")}
        arguments = dict(scope_input=scope_input, scope_raw=scope_raw, bootstrap_raw=bootstrap_raw,
            recipe=f["value"]["recipeOriginals"], bundle={"originals": components})
        inputs._exported(observed, **arguments)
        for field in ("bootstrapObservationOriginal", "phaseScopeOriginal", "phaseBundleOriginal", "assignmentOriginal",
                "closureOriginal", "keyConfigurationOriginal", "admissionAuthorizationOriginal"):
            changed = exported | {field: "{}"}
            with self.subTest(field=field), self.assertRaises(ValueError):
                inputs._exported(observed | {"publicAdmissionOriginal": canonical(changed).decode("ascii")}, **arguments)

    def test_missing_real_scope_launch_or_export_never_produces_constructed_input(self):
        selected = inputs.profile.BY_NAME["driver-constructed"][1]
        with self.assertRaises(ValueError):
            inputs.compose(selected, {"continuationPolicy": self.case["fragment"]}, prior=self.case["prior"],
                observations={"constructed-admission": {}}, supervisor_observation=self.case["observed"], **self.case["clocks"])
        observed = {name: "{}" for name in inputs.continuation.OBSERVATION_FIELDS}
        with self.assertRaises(KeyError):
            inputs.compose(selected, {"continuationPolicy": self.case["fragment"]}, prior=self.case["prior"],
                observations={"constructed-admission": observed}, supervisor_observation=self.case["observed"], **self.case["clocks"])


if __name__ == "__main__": unittest.main()
