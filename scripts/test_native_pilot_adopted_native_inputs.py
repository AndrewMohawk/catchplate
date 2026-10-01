#!/usr/bin/env python3
"""Pure adopted candidate controls, not independent approval or live admission.

The reused fixture has authentic deterministic test signatures for ten non-core
endpoint C9/key/closure chains. Earlier owner/adoption entries here are labelled
source projections only: this is deliberately not a complete facade prefix,
native adoption result, received core, native grant ceremony or installed pilot.
Missing late predecessors must refuse, rather than being replaced with invented
history, resource or ciphertext success. No production signer or owner runs.
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
from serverware import native_pilot_adopted_native_inputs as inputs
from serverware import native_pilot_adopted_phase_profile as phase
from serverware import native_pilot_service_material as material
from test_native_pilot_adopted_closure import fixture as signed_fixture, input_for as closure_input
from test_native_pilot_key_authorizations import build, clocks, expected_payload, signed_result
from test_native_pilot_launch_authorizations import transport, set_credentials, signed as signed_authorization
from test_native_pilot_generation_scope import NOW, encoded, ASSIGNMENT_DOMAIN, key_fixture, signed_message
from test_native_pilot_closure_set import (canonical, sha, synthetic, frame, scope_fixture,
    EXPECTED_SCOPE_VALUES, EXPECTED_SCOPE_ROOTS)


def record(raw, output=None):
    return {"input": raw, "result": {} if output is None else {"original": output.decode("ascii"), "sha256": sha(output)}}


def fixture():
    f = signed_fixture()
    envelope = json.loads(f["recipe_originals"]["assignmentOriginal"])
    envelope["payload"]["observationWindow"].update(requestCommitmentKeyId=synthetic("independent-request-key"),
        requestCommitmentKeyEpoch=7)
    envelope["payloadSha256"] = sha(canonical(envelope["payload"]))
    envelope["signature"] = encoded(key_fixture("assignment")[0].sign(signed_message(ASSIGNMENT_DOMAIN, envelope["payload"])))
    f["recipe_originals"]["assignmentOriginal"] = canonical(envelope).decode("ascii")
    binding = json.loads(f["measured"]["configurationBindingOriginal"])
    binding["assignmentPayloadSha256"] = envelope["payloadSha256"]
    binding_sha = frame("serverware.policyShadowProductionCustodyConfiguration/v2", binding)
    proof = scope_fixture(envelope); proof["production_configuration_binding_sha256"] = binding_sha
    proof["binding_sha256"] = frame("serverware.policyShadowProductionCustodyProofScope/v2",
        [proof[name] for name in EXPECTED_SCOPE_VALUES + EXPECTED_SCOPE_ROOTS])
    f["measured"].update(configurationBindingOriginal=canonical(binding).decode("ascii"),
        configurationBindingSha256=binding_sha, proofScopeOriginal=canonical(proof).decode("ascii"))
    f["measured"]["production"]["expectedConfigurationBindingSha256"] = binding_sha
    # Provisioner's public commitments are explicit synthetic values. This
    # does not generate or assert possession of any ciphertext or secret.
    for role in f["adopted_roles"]:
        credentials = copy.deepcopy(json.loads(f["deliveries"][role])["payload"]["credentials"])
        credentials.append({"name": "shadow-encrypted-role-inventory", "original": {
            "path": "/etc/serverware/synthetic-ciphertext-" + role + ".json",
            "sha256": transport(role)["encryptedInventorySha256"]}, "length": 256, "signing": None})
        set_credentials(f, role, credentials)
        f["fragment"][role]["credentials"] = credentials
    source = {"currentTrustOriginal": f["recipe_originals"]["trustOriginal"],
        "currentTrustSha256": f["recipe_originals"]["trustSha256"],
        "currentAssignmentOriginal": f["recipe_originals"]["assignmentOriginal"],
        "currentClosureSetOriginal": f["recipe_originals"]["closureSetOriginal"],
        "currentConfigurationBindingSha256": f["measured"]["configurationBindingSha256"],
        "currentProofScopeOriginal": f["measured"]["proofScopeOriginal"]}
    prior = {
        "install-precreation": record(canonical({"nativeColdOriginals": f["cold"],
            "cohortConfigurationOriginal": f["owner_configuration_raw"].decode("ascii")})),
        "cohort-precreation": record(b"{}", f["window_raw"]),
        # Literal source projection, NOT a validated or signed adoption entry.
        "publication-adoption": record(canonical({"validationInputOriginal": canonical(source).decode("ascii")})),
    }
    for role in f["adopted_roles"]:
        prior["native-delivery-" + role] = record(f["delivery_inputs"][role], f["deliveries"][role])
        first = build(f, "role-keys", role, adopted=True)
        first_raw, _ = signed_result(expected_payload(f, "role-keys", role), "role-keys")
        second = build(f, "admission", role, role_key_raw=first_raw, adopted=True)
        second_raw, _ = signed_result(expected_payload(f, "admission", role, role_key_raw=first_raw), "admission")
        prior["native-role-keys-" + role] = record(first, first_raw)
        prior["native-key-admission-" + role] = record(second, second_raw)
    observed = {"nativeActivations": copy.deepcopy(f["activations"]),
        "cohortObservationOriginal": f["observation_raw"].decode("ascii")}
    return {"source": f, "prior": prior,
        "observations": {"endpoint-inputs": {}, "endpoint-deliveries": copy.deepcopy(observed),
            "service-originals": copy.deepcopy(observed)},
        "supervisor_observation": {"recipeOriginals": copy.deepcopy(f["recipe_originals"]),
            "measuredConfiguration": copy.deepcopy(f["measured"])}, "clocks": clocks(f)}


class AdoptedNativeCandidateControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.case = fixture()

    def compose(self, name, selection, *, case=None, **clock_changes):
        case = self.case if case is None else case
        return inputs.compose(phase.BY_NAME[name][1], selection, prior=case["prior"],
            observations=case["observations"], supervisor_observation=case["supervisor_observation"],
            **{**case["clocks"], **clock_changes})

    def test_fixed_catalogue_selection_covers_only_selected_families(self):
        supported = [job for _, job in phase.BY_NAME.values()
            if job.family in inputs.FAMILIES and job.role != "bridge"]
        self.assertEqual(sum(job.family == "delivery" for job in supported), 11)
        self.assertEqual(sum(job.family == "native-key" for job in supported), 22)
        self.assertEqual(sum(job.family == "launch" for job in supported), 11)
        for job in supported:
            fields = inputs.selection_fields(job)
            self.assertEqual(type(fields), tuple)
            self.assertEqual(len(fields), len(set(fields)))
        for _, job in phase.BY_NAME.values():
            if job not in supported:
                with self.subTest(job=job.name), self.assertRaises(ValueError): inputs.selection_fields(job)
        with self.assertRaises(ValueError): inputs.selection_fields({"name": supported[0].name})

    def test_ten_actual_fixture_c9_inputs_are_reproduced_without_array_object_codec(self):
        f = self.case["source"]
        for role in f["adopted_roles"]:
            with self.subTest(role=role):
                raw = self.compose("native-delivery-" + role, {"credentials": f["fragment"][role]["credentials"]})
                self.assertEqual(raw, f["delivery_inputs"][role])
                self.assertEqual(json.loads(json.loads(raw)["activationOriginal"]), f["activations"][role])

    def test_ten_key_and_admission_candidates_equal_existing_signed_chain_inputs(self):
        f = self.case["source"]
        for role in f["adopted_roles"]:
            for operation, prefix, policy in (("role-keys", "native-role-keys-", f["policy"][role]),
                    ("admission", "native-key-admission-", {})):
                with self.subTest(role=role, operation=operation):
                    self.assertEqual(self.compose(prefix + role, policy), self.case["prior"][prefix + role]["input"])

    def test_ten_closure_candidates_equal_existing_exact_hot12_inputs(self):
        interval = {"issuedAtUnixNanos": NOW - 500_000_000, "expiresAtUnixNanos": NOW + 500_000_000}
        for role in self.case["source"]["adopted_roles"]:
            with self.subTest(role=role):
                self.assertEqual(self.compose("native-closure-" + role, interval),
                    canonical(closure_input(self.case["source"], role)))

    def test_verifier_and_supplied_ciphertext_transport_are_selected_not_generated(self):
        role = "publicationReconciliation"
        interval = {"issuedAtUnixNanos": NOW - 100_000_000, "expiresAtUnixNanos": NOW + 100_000_000}
        verifier = json.loads(self.compose("native-verifier-transport-" + role, interval | {"parentPort": 11443}))
        self.assertEqual(verifier["apiVersion"], inputs.phase.commands.verifier.ADOPTED_API)
        self.assertEqual(verifier["parentPort"], 11443)
        literal = canonical(transport(role)).decode("ascii")
        encrypted = json.loads(self.compose("native-encrypted-delivery-" + role, interval | {"transportOriginal": literal}))
        self.assertEqual(encrypted["transportOriginal"], literal)
        self.assertEqual(encrypted["operation"], "delivery")
        self.assertEqual(encrypted["roleKeyOriginal"], self.case["prior"]["native-role-keys-" + role]["result"]["original"])

    def test_request_commitment_requires_actual_signed_prior_for_extended_transport(self):
        case = {**self.case, "prior": copy.deepcopy(self.case["prior"])}
        role = "commitRequest"
        assignment = json.loads(case["source"]["recipe_originals"]["assignmentOriginal"])["payload"]
        window = assignment["observationWindow"]
        interval = {"issuedAtUnixNanos": NOW - 100_000_000, "expiresAtUnixNanos": NOW + 100_000_000}
        descriptor = {"keyId": window["requestCommitmentKeyId"], "keyEpoch": window["requestCommitmentKeyEpoch"],
            "secretSha256": synthetic("explicit-unprovisioned-request-secret")}
        raw = self.compose("native-request-commitment-" + role,
            interval | {"requestCommitmentOriginal": canonical(descriptor).decode("ascii")}, case=case)
        context = inputs.phase.commands.encrypted.prepare_input("request-commitment", role, raw, **case["clocks"])
        signed, _ = signed_authorization(case["source"], "request-commitment", role, context["payload"])
        case["prior"]["native-request-commitment-" + role] = record(raw, signed)
        selection = interval | {"transportOriginal": canonical(transport(role)).decode("ascii")}
        value = json.loads(self.compose("native-encrypted-delivery-" + role, selection, case=case))
        self.assertEqual(value["requestCommitmentOriginal"], signed.decode("ascii"))
        bad = json.loads(signed); bad["signature"] = encoded(bytes(64))
        case["prior"]["native-request-commitment-" + role] = record(raw, canonical(bad))
        with self.assertRaises(InvalidSignature): self.compose("native-encrypted-delivery-" + role, selection, case=case)

    def test_literal_measured_and_recipe_sources_cannot_drift(self):
        name = "native-role-keys-publicationReconciliation"
        policy = self.case["source"]["policy"]["publicationReconciliation"]
        for group, field, replacement in (("measuredConfiguration", "configurationBindingSha256", synthetic("other-binding")),
                ("recipeOriginals", "trustOriginal", "{}"), ("recipeOriginals", "assignmentOriginal", "{}"),
                ("recipeOriginals", "closureSetOriginal", "{}")):
            observed = copy.deepcopy(self.case["supervisor_observation"]); observed[group][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.compose(name, policy, case={**self.case, "supervisor_observation": observed})

    def test_selection_cannot_override_process_payload_or_prior_originals(self):
        role = "publicationReconciliation"
        selected = {"credentials": self.case["source"]["fragment"][role]["credentials"]}
        for field in ("activation", "processId", "payloadOriginal", "configurationOriginal", "role", "approved"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.compose("native-delivery-" + role, selected | {field: 1})
        with self.assertRaises(ValueError): self.compose("native-key-admission-" + role, {"roleKeyOriginal": "{}"})

    def test_actual_c9_activation_signature_and_original_clocks_remain_required(self):
        role = "publicationReconciliation"; name = "native-role-keys-" + role
        policy = self.case["source"]["policy"][role]
        for change in ({"now_boottime_ns": int(self.case["source"]["window"]["startupDeadlineBoottimeNs"])},
                {"now_unix_ns": policy["expiresAtUnixNanos"]}, {"boot": (encoded(bytes([9]) * 16), 4, 5)}):
            with self.subTest(change=change), self.assertRaises(ValueError): self.compose(name, policy, **change)
        prior = copy.deepcopy(self.case["prior"])
        raw = json.loads(prior["native-delivery-" + role]["result"]["original"])
        raw["signatureBase64url"] = encoded(bytes(64))
        prior["native-delivery-" + role] = record(prior["native-delivery-" + role]["input"], canonical(raw))
        with self.assertRaises(InvalidSignature): self.compose(name, policy, case={**self.case, "prior": prior})
        observations = copy.deepcopy(self.case["observations"])
        observations["endpoint-deliveries"]["nativeActivations"][role][0]["name"] = "unapproved-listener"
        with self.assertRaises(ValueError):
            self.compose("native-delivery-" + role, {"credentials": self.case["source"]["fragment"][role]["credentials"]},
                case={**self.case, "observations": observations})

    def test_core_and_late_grant_launch_material_predecessors_are_not_fabricated(self):
        with self.assertRaises(KeyError): self.compose("native-delivery-retrieval", {"credentials": []})
        for name, selection in (("native-service-persistence", {"verifierSettings": {},
                "issuedAtUnixNanos": NOW - 1, "expiresAtUnixNanos": NOW + 1, "initialization": "fresh-persistence"}),
                ("install-launch-persistence", {"timeBootstrap": {}}),
                ("service-material", {"policy": {"apiVersion": material.ADOPTED_POLICY_API,
                    "initialization": "adopted-persistence-and-generation"}})):
            with self.subTest(job=name), self.assertRaises((ValueError, KeyError)):
                self.compose(name, selection)

    def test_publication_literal_predecessor_join_includes_all_five_roles(self):
        # This isolates the literal join, NOT public signature or grant admission.
        prior = copy.deepcopy(self.case["prior"])
        prior["native-delivery-retrieval"] = record(b'{"synthetic":"retrieval-input"}', b'{"synthetic":"retrieval-output"}')
        prior["publication-adoption"]["result"] = {"original": '{"synthetic":"adoption-output"}',
            "sha256": sha(b'{"synthetic":"adoption-output"}')}
        value = {"deliveryInputOriginal": prior["native-delivery-publicationReconciliation"]["input"].decode("ascii"),
            "deliveryOriginal": prior["native-delivery-publicationReconciliation"]["result"]["original"],
            "adoptionAuthorizationOriginal": prior["publication-adoption"]["result"]["original"],
            "adoptionValidationInputOriginal": json.loads(prior["publication-adoption"]["input"])["validationInputOriginal"],
            "retrievalDeliveryInputOriginal": prior["native-delivery-retrieval"]["input"].decode("ascii"),
            "retrievalDeliveryOriginal": prior["native-delivery-retrieval"]["result"]["original"], "ordinaryServices": {}}
        for role in phase.g.ROLES:
            row = {"runtimeOriginal": canonical({"syntheticRuntime": role}).decode("ascii"),
                "historyOriginal": canonical({"syntheticHistory": role}).decode("ascii")}
            result = canonical({"syntheticGeneration": role})
            prior["ordinary-generation-" + role] = record(canonical({"services": {role: row}}), result)
            value["ordinaryServices"][role] = row | {"generationGrantOriginal": result.decode("ascii")}
        job = phase.BY_NAME["native-service-publication"][1]
        phase._native(job, value, prior, {})
        del value["ordinaryServices"][phase.g.ROLES[1]]
        with self.assertRaises(ValueError): phase._native(job, value, prior, {})

    def test_selected_material_projects_literals_without_mutating_complete_service_input(self):
        # Source projection only; prepare_bundle authenticates both complete
        # service input/signature pairs before it invokes this helper.
        source = self.case["source"]
        item = {"deliveryInputOriginal": source["delivery_inputs"]["persistence"].decode("ascii"),
            "adoptionValidationInputOriginal": json.loads(self.case["prior"]["publication-adoption"]["input"])["validationInputOriginal"]}
        original = copy.deepcopy(item)
        projected = material._adopted_persistence_sources(item)
        delivery = json.loads(item["deliveryInputOriginal"])
        for target, field in (("coldConfigurationOriginal", "configurationOriginal"),
                ("cohortConfigurationOriginal", "ownerConfigurationOriginal"),
                ("precreationOriginal", "windowOriginal"), ("observationOriginal", "observationOriginal")):
            self.assertEqual(projected[target], delivery[field])
        self.assertEqual(projected["assignmentPayloadOriginal"],
            canonical(json.loads(source["recipe_originals"]["assignmentOriginal"])["payload"]).decode("ascii"))
        self.assertEqual(item, original)


if __name__ == "__main__": unittest.main()
