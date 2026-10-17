#!/usr/bin/env python3
"""Pure selected graph/public-transcript controls, never successful owners.

No publisher, validator process, pipe, key FD, service or retained core is
constructed. The signature control uses an explicitly synthetic public decision;
it does not replace the mandatory real native validator in the actual executor.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from catchplate import native_pilot_phase_execution as old
from catchplate import native_pilot_adopted_phase_profile as profile
from catchplate import native_pilot_adopted_phase_execution as execution
from test_native_pilot_adopted_current_head import fixture

p = profile.p
FAILURES = (ValueError, KeyError, TypeError, InvalidSignature)


def installation_sources():
    source = fixture()
    f, args = source["fixture"], source["args"]
    value = {"apiVersion": profile.INSTALLATION_API, "launchOriginal": args["launch_raw"].decode("ascii"),
        "preparationOriginal": args["preparation_raw"].decode("ascii"),
        "resourcesOriginal": args["resources_raw"].decode("ascii"),
        "driverConfigurationOriginal": args["driver_configuration_raw"].decode("ascii"),
        "driverWindowOriginal": args["driver_window_raw"].decode("ascii"),
        "coldOriginals": {role: p.canonical(f["cold"][role]).decode("ascii") for role in profile.g.ROLES},
        "historyOriginals": {role: f["histories"][role].decode("ascii") for role in profile.g.ROLES},
        "runtimeOriginals": {role: f["runtimes"][role].decode("ascii") for role in profile.g.ROLES}}
    first = {"ordinaryLaunchOriginal": value["launchOriginal"], "ordinaryColdOriginals": value["coldOriginals"],
        "driverConfigurationOriginal": value["driverConfigurationOriginal"], "driverWindowOriginal": value["driverWindowOriginal"]}
    prior = {"install-precreation": {"input": p.canonical(first), "result": {}}}
    def result(raw): return {"input": b"{}", "result": {"original": raw.decode("ascii"), "sha256": p.sha(raw)}}
    for role in profile.g.ROLES:
        prior["ordinary-initial-assemble-" + role] = result(f["histories"][role])
    primary = json.loads(f["histories"][profile.g.ROLES[-1]])["initialCheckpoint"]["payload"]["endpointRole"]
    remaining = [role for role in old.initial_profile.HELPER_ENDPOINT_ROLES if role != primary]
    for slot, role in enumerate(remaining, 1):
        prior["ordinary-helper-initial-assemble-slot" + str(slot)] = result(f["helper_histories"][role])
    observed = {"ordinaryPreparationOriginal": value["preparationOriginal"], "ordinaryInitialResourcesOriginal": value["resourcesOriginal"]}
    return value, prior, observed


class AdoptedPhaseControls(unittest.TestCase):
    def test_separate_catalogue_and_legacy_key_inventory(self):
        self.assertEqual(sum(map(len, old.JOBS.values())), 164)
        self.assertEqual(len(old.KEY_PURPOSES), 113)
        self.assertEqual(len(profile.BY_NAME), 176)
        self.assertEqual(len(profile.KEY_PURPOSES), 123)
        self.assertEqual(tuple(profile.JOBS), tuple(old.JOBS))
        self.assertNotEqual(profile.APPROVAL_ROOT, old.APPROVAL_ROOT)

    def test_all_actual_handler_families_are_selected(self):
        execution.require_complete_coverage()
        self.assertEqual(len(profile.ENDPOINTS), 11)
        self.assertEqual(len(profile.COMPOSITE), 4)
        self.assertEqual(len(profile.KEY_INFO), 22)
        self.assertEqual(len(profile.AUTH_INFO), 34)

    def test_shared_publication_census_and_independent_aggregate_byte_bound(self):
        from catchplate import native_pilot_publication as publication
        from catchplate import native_pilot_public_inputs as public_inputs
        from catchplate import native_pilot_adopted_endpoint_plan as endpoints

        # Only purpose-bearing signed outputs use the executor's shared owner.
        # Precreation, ordinary/runtime/material and each native launch install
        # have their own actual publishers; authorizations with no purpose stay
        # in the transcript and are not additional shared publication slots.
        signed = tuple(job.purpose for rows in profile.JOBS.values() for job in rows if job.purpose is not None)
        self.assertEqual(len(signed), 51)
        shared = signed + (old.phase_two.PURPOSE,) + endpoints.PURPOSES
        self.assertEqual(len(shared), 56)
        self.assertEqual(len(set(shared)), len(shared))
        self.assertLessEqual(len(shared), publication.MAX_ORIGINALS)
        reader = tuple("native-cold-" + role for role in profile.COMPOSITE) + (
            "publication-adoption",) + endpoints.PURPOSES + (old.phase_two.PURPOSE,)
        self.assertEqual(len(reader), len(set(reader)))
        self.assertEqual(len(reader), 10)
        self.assertLessEqual(len(reader), public_inputs.MAX_ORIGINALS)
        additional_bound = sum(publication.LIMITS[purpose] for purpose in endpoints.PURPOSES)
        self.assertEqual(additional_bound, 4 * 1024 * 1024 + 52 * 1024)
        self.assertLess(additional_bound, publication.MAX_PUBLIC_BYTES)
        self.assertEqual(publication.MAX_PUBLIC_BYTES, public_inputs.MAX_PUBLIC_BYTES)
        # Counts do not prove all allowed maxima fit together or a real graph
        # was admitted. Actual bytes still consume the original aggregate cap.
        def maximum(purpose):
            if purpose in execution.public_profile.LIMITS:
                return execution.public_profile.LIMITS[purpose]
            if purpose in old.launch_install.ADOPTED_PURPOSES:
                return old.launch_install.ADOPTED_PURPOSES[purpose]
            return publication.LIMITS[purpose]
        self.assertGreater(sum(maximum(purpose) for purpose in shared), publication.MAX_PUBLIC_BYTES)

    def test_initial_install_and_adoption_precede_first_endpoint_input(self):
        names = [job.name for job in profile.JOBS["endpoint-inputs"]]
        self.assertEqual(len(names), 48)
        self.assertEqual(names[40], "install-ordinary-runtime")
        self.assertEqual(names[41:46], ["ordinary-delivery-" + role for role in profile.g.ROLES])
        self.assertEqual(names[-2:], ["publication-adoption", "endpoint-inputs"])
        self.assertFalse(any(job.family == "ordinary-generation" for job in profile.JOBS["endpoint-inputs"]))

    def test_generation_after_real_recipe_and_publication_before_retrieval(self):
        names = [job.name for job in profile.JOBS["service-originals"]]
        self.assertEqual(names[:5], ["ordinary-generation-" + role for role in profile.g.ROLES])
        self.assertLess(names.index("native-service-publication"), names.index("native-service-retrieval"))
        for role in profile.PUBLICATION_ROLES:
            self.assertGreater(names.index("ordinary-publication-" + role), names.index("native-service-retrieval"))
        self.assertEqual(names[-1], "service-material")

    def test_exact_prefix_refuses_missing_future_and_foreign_job(self):
        observed = {"bootstrap-admission": {}}
        self.assertEqual(profile._prefix("driver-bootstrap", "bootstrap-admission", {}, observed).name, "driver-bootstrap")
        for prior, observations in (({"later": {"input": b"{}", "result": {}}}, observed),
                ({}, {}), ({}, {**observed, "endpoint-inputs": {}})):
            with self.subTest(prior=list(prior), observations=list(observations)), self.assertRaises(FAILURES):
                profile._prefix("driver-bootstrap", "bootstrap-admission", prior, observations)
        with self.assertRaises(FAILURES): profile.job_index("endpoint-inputs", "ordinary-generation-" + profile.g.ROLES[0])

    def test_nested_complete_original_bound_does_not_use_four_mib_codec(self):
        raw = p.canonical({"literal": "x" * (4 * 1024 * 1024 + 1)})
        self.assertEqual(profile._raw(raw.decode("ascii")), raw)
        with self.assertRaises(FAILURES): profile._raw(raw.decode("ascii"), 4 * 1024 * 1024)

    def test_installed_history_runtime_association_uses_all_eight_originals(self):
        value, prior, observed = installation_sources()
        profile._installation(value, prior, observed)
        changed = copy.deepcopy(value)
        helper = json.loads(changed["runtimeOriginals"][profile.g.ROLES[-1]])
        helper["initialEndpointHistories"].pop(next(iter(helper["initialEndpointHistories"])))
        changed["runtimeOriginals"][profile.g.ROLES[-1]] = p.canonical(helper).decode("ascii")
        with self.assertRaises(FAILURES): profile._installation(changed, prior, observed)

    def test_installed_source_substitution_is_not_a_new_approval(self):
        value, prior, observed = installation_sources()
        for field in ("launchOriginal", "preparationOriginal", "resourcesOriginal", "driverWindowOriginal"):
            changed = copy.deepcopy(value); changed[field] = "{}"
            with self.subTest(field=field), self.assertRaises(FAILURES): profile._installation(changed, prior, observed)

    def test_adoption_result_exact_three_field_authority_and_signature(self):
        key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"SYNTHETIC adopted phase result authority").digest())
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        digest = p.sha(bytes.fromhex("302a300506032b6570032100") + public)
        payload = {"authority": {"keyId": digest, "keySpkiSha256": digest, "publicKeyBase64url": p.encoded(public)},
            "syntheticDecision": "signature-helper-only-not-native-validation"}
        prepared = {"payload": payload, "payloadOriginal": p.canonical(payload),
            "domain": "catchplate.nativePublicationAdoptionAuthorization.signature/v2"}
        result = {"payload": payload, "signature": p.encoded(key.sign(profile.adoption.message(prepared)))}
        raw = p.canonical(result)
        self.assertEqual(profile._adoption_result(raw, prepared), raw)
        result["signature"] = p.encoded(bytes(64))
        with self.assertRaises(FAILURES): profile._adoption_result(p.canonical(result), prepared)
        wrong = copy.deepcopy(prepared)
        wrong["payload"]["authority"]["role"] = "not-a-three-field-authority"
        wrong["payloadOriginal"] = p.canonical(wrong["payload"])
        with self.assertRaises(FAILURES): profile._adoption_result(raw, wrong)

    def test_fixed_cli_selectors_and_adoption_private_read_order(self):
        script = (ROOT / "scripts/run_native_pilot_authority_coordinator.py").read_text()
        ast.parse(script)
        for literal in ("--run-native-pilot", "--run-adopted-native-pilot", "--run-native-genesis-listener",
                "--intake-configuration-fd", "ProcessPreparationError"):
            self.assertIn(literal, script)
        tree = ast.parse((ROOT / "catchplate/native_pilot_adopted_phase_execution.py").read_text())
        method = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_adoption")
        calls = [(node.lineno, node.func.attr) for node in ast.walk(method)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("validate", "sign")]
        self.assertLess(next(line for line, name in calls if name == "validate"), next(line for line, name in calls if name == "sign"))


if __name__ == "__main__":
    unittest.main()
