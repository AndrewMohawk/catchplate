#!/usr/bin/env python3
"""Bounded pure commissioning controls, never live-owner or approval evidence.

All process, resource, time and key values are synthetic test fixtures. No
composer owner, protected file, signer entrypoint or service is exercised.
Signature fixtures are deterministic in-memory test data only.
"""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import sys
import unittest

from cryptography.exceptions import InvalidSignature

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))

from serverware import native_pilot_phase_execution as execution
from serverware import native_pilot_ordinary_initial_profile as initial_profile
from serverware import native_pilot_publication_profiles as publication
from serverware import native_pilot_supervisor as supervisor
from serverware import native_pilot_supervisor_initial_history as composer
from serverware import native_pilot_supervisor_policy as policy
from test_native_pilot_ordinary_initial import (
    ANCHOR_FIELDS, SIGNATURE_FIELDS, checkpoint as signed_checkpoint, fixture, sign_anchor,
)
from test_native_pilot_ordinary_keys import ROLES, canonical, encoded, labelled, sha

OPERATIONS = ("checkpoint", "root-anchor", "checkpoint-anchor", "service-anchor", "assemble")
ROLE = ROLES[0]


def policy_fixture():
    f = fixture()
    row = {"authorities": f["public"], "endpointRole": "settlement-store",
        **{name: f["state"][name] for name in ("endpointGeneration", "serviceGeneration", "operationGeneration",
            "durableEpoch", "deploymentGenerationSha256")},
        "revocationGenerationHighWater": 1, "revocationRootSha256": labelled("approved-revocation"),
        "validity": "observed-initial-resources-through-original-lifetime"}
    value = {"apiVersion": "serverware.nativePilotSupervisorOrdinaryInitialPolicy/v1",
        "services": {role: copy.deepcopy(row) for role in ROLES}}
    cold = {role: canonical(f["cold"][role]).decode("ascii") for role in ROLES}
    # Pure-validator context only, not a complete/approved driver configuration.
    public = {name: {"publicKeyBase64url": encoded(bytes([number]) * 32),
        "keyId": sha(bytes([number]) * 32)} for number, name in enumerate(("bootstrapAuthority",
            "phaseTwoAuthority", "constructedAdmissionAuthority"), 41)}
    driver = {name: public[name] for name in ("bootstrapAuthority", "phaseTwoAuthority")}
    driver["lifecycle"] = {"constructedAdmissionAuthority": public["constructedAdmissionAuthority"]}
    return value, cold, driver


def stage_fixture(operation):
    f = fixture()
    history = f["wrapper"]["history"]
    payload = copy.deepcopy(f["wrapper"]["initialCheckpoint"]["payload"])
    payload["validUntilBoottime"]["absoluteBoottimeNanos"] = int(f["state"]["lifetimeDeadlineBoottimeNs"])
    checkpoint = signed_checkpoint(payload, f["public"]["checkpoint"], f["keys"]["checkpoint"])
    f["wrapper"]["initialCheckpoint"] = checkpoint
    history["firstRetainedEpoch"]["retainedEpoch"]["checkpointSha256"] = checkpoint["checkpointSha256"]
    sign_anchor(history, f["keys"])
    anchor = history["firstRetainedEpoch"]
    records = {}
    for name, signature in zip(("root", "checkpoint", "service"), SIGNATURE_FIELDS, strict=True):
        records[name] = {"apiVersion": "serverware.custodyOrdinaryInitialAnchorSignature/v1", "signer": name,
            "anchorPayloadSha256": sha(canonical([anchor[field] for field in ANCHOR_FIELDS])),
            "keyId": f["public"][name]["keyId"], "keySpkiSha256": f["public"][name]["keySpkiSha256"],
            "signatureBase64": anchor[signature]}
    # The pure result verifier does not authenticate the driver window or live
    # process: real compose owns those joins. This placeholder is deliberately
    # not a valid signature for the synthetic window payload.
    signed_window = {"apiVersion": "serverware.nativeShadowDriverBootstrapWindow/v1", "payload": f["window"],
        "signatureBase64url": encoded(b"S" * 64)}
    value = {"apiVersion": "serverware.nativePilotOrdinaryInitialAuthorityInput/v1", "operation": operation,
        "driverConfigurationOriginal": canonical({"syntheticUncheckedContext": True}).decode("ascii"),
        "driverWindowOriginal": canonical(signed_window).decode("ascii"),
        "launchOriginal": canonical(f["launch"]).decode("ascii"),
        "configurationOriginal": canonical(f["cold"][ROLE]).decode("ascii"),
        "preparationOriginal": canonical(f["preparation"]).decode("ascii"),
        "resourcesOriginal": canonical(f["resources"]).decode("ascii"),
        "initialStateOriginal": canonical(f["state"]).decode("ascii"), "authorities": f["public"],
        "payloadOriginal": canonical(checkpoint["payload"]).decode("ascii")}
    if operation != "checkpoint":
        value["initialCheckpointOriginal"] = canonical(checkpoint).decode("ascii")
    if operation == "assemble":
        value["anchorSignatures"] = {name: canonical(record).decode("ascii") for name, record in records.items()}
        output = f["wrapper"]
    elif operation == "checkpoint":
        output = checkpoint
    else:
        output = records[operation.removesuffix("-anchor")]
    raw = canonical(output)
    result = {"original": raw.decode("ascii"), "sha256": sha(raw)}
    if operation == "assemble":
        result["pin"] = {"path": "/etc/serverware/native-pilot-inputs/ordinary-initial-history-" + ROLE + ".json",
            "sha256": sha(raw)}
    return value, result, raw


class SyntheticInitialCommissioningControls(unittest.TestCase):
    def test_closed_role_major_order_and_distinct_capabilities(self):
        phase = "service-originals"
        def source_jobs(names):
            first = execution.job_index(phase, names[0]) - 1
            selected = execution.JOBS[phase][first:first + len(names)]
            self.assertEqual(tuple(job.name for job in selected), tuple(names))
            for offset, name in enumerate(names):
                self.assertEqual(execution.job_index(phase, name), first + offset + 1)
            supported_first = supervisor.SUPPORTED_JOBS.index((phase, names[0]))
            self.assertEqual(supervisor.SUPPORTED_JOBS[supported_first:supported_first + len(names)],
                tuple((phase, name) for name in names))
            return selected

        expected = tuple("ordinary-initial-" + operation + "-" + role
            for role in ROLES for operation in OPERATIONS)
        jobs = execution.JOBS["service-originals"][:25]
        self.assertEqual(tuple(job.name for job in jobs), expected)
        self.assertEqual(len(execution.KEY_PURPOSES), 108)
        initial_keys = set()
        for job, (role, operation) in zip(jobs,
                ((role, operation) for role in ROLES for operation in OPERATIONS), strict=True):
            self.assertEqual((job.family, job.role, job.maximum), ("ordinary-initial", role, 8 * 1024 * 1024))
            self.assertEqual(execution.INITIAL_JOB_INFO[job.name], (role, operation))
            key = None if operation == "assemble" else "ordinary-initial-" + {
                "checkpoint": "checkpoint", "root-anchor": "root", "checkpoint-anchor": "checkpoint",
                "service-anchor": "service"}[operation] + "-" + role
            self.assertEqual(job.key, key)
            self.assertEqual(job.purpose, "ordinary-initial-history-" + role if operation == "assemble" else None)
            if key is not None:
                initial_keys.add(key)
        self.assertEqual(len(initial_keys), 15)
        self.assertTrue(initial_keys.issubset(execution.KEY_PURPOSES))
        self.assertEqual(initial_profile.INITIAL_CREDENTIAL_PATHS,
            {role: "/etc/serverware/custody-" + role + "-initial-history.json" for role in ROLES})
        for role in ROLES:
            self.assertNotEqual(initial_profile.INITIAL_CREDENTIAL_PATHS[role],
                publication.DESTINATIONS["ordinary-initial-history-" + role])
        self.assertEqual(supervisor.SUPPORTED_JOBS[7:32], tuple(("service-originals", name) for name in expected))
        source_jobs(tuple("ordinary-delivery-" + role for role in ROLES))
        source_jobs(tuple("ordinary-generation-" + role for role in ROLES))
        endpoints = ("retrieval", "persistence", "trustedTime", "generationInstall", "commitRequest",
            "ingressAdmission", "terminalAppend", "dispatchBarrier", "activeEffectBarrier", "activeEffectCommit")
        pairs = tuple((role, operation) for role in endpoints for operation in ("role-keys", "admission"))
        key_names = tuple(("native-role-keys-" if operation == "role-keys" else "native-key-admission-")
            + role for role, operation in pairs)
        self.assertEqual(tuple(job.name for job in execution.KEY_AUTHORIZATION_JOBS), key_names)
        self.assertEqual(source_jobs(key_names), execution.KEY_AUTHORIZATION_JOBS)
        for job, pair in zip(execution.KEY_AUTHORIZATION_JOBS, pairs, strict=True):
            self.assertEqual(execution.KEY_AUTHORIZATION_JOB_INFO[job.name], pair)
            self.assertEqual((job.family, job.purpose, job.key, job.maximum),
                ("native-key", None, job.name, 32 * 1024 * 1024))
        native_names = tuple("native-service-" + operation for operation in ("commitRequest", "ingress", "ledger",
            "terminal", "dispatchBarrier", "activeEffectBarrier", "activeEffectCommit", "retrieval", "persistence", "trustedTime"))
        native_names += ("native-generation-install-grant",)
        source_jobs(native_names)
        transition_names = ("ordinary-dispatch-durable-recovery-store", "ordinary-dispatch-current-signature-authority",
            "ordinary-head", "ordinary-cleanup", "ordinary-current")
        source_jobs(transition_names)
        launch_pairs = tuple((role, operation) for role in endpoints for operation in
            (("closure", "request-commitment", "encrypted-delivery", "verifier-transport")
             if role == "commitRequest" else ("closure", "encrypted-delivery", "verifier-transport")))
        launch_names = tuple("native-" + operation + "-" + role for role, operation in launch_pairs)
        self.assertEqual(len(launch_names), 31)
        self.assertEqual(tuple(job.name for job in execution.LAUNCH_AUTHORIZATION_JOBS), launch_names)
        self.assertEqual(source_jobs(launch_names), execution.LAUNCH_AUTHORIZATION_JOBS)
        for job, pair in zip(execution.LAUNCH_AUTHORIZATION_JOBS, launch_pairs, strict=True):
            self.assertEqual(execution.LAUNCH_AUTHORIZATION_JOB_INFO[job.name], pair)
            self.assertEqual((job.family, job.purpose, job.key), ("native-launch-authorization", None, job.name))
        endpoint_jobs = source_jobs(tuple("install-launch-" + role for role in endpoints))
        for job, role in zip(endpoint_jobs, endpoints, strict=True):
            self.assertEqual((job.family, job.role, job.purpose, job.key), ("launch", role, None, None))
        material, = source_jobs(("service-material",))
        self.assertEqual(execution.job_index(phase, material.name), len(execution.JOBS[phase]))
        self.assertEqual(material.maximum, 64 * 1024 * 1024)
        service_names = (expected + tuple(job.name for job in execution.HELPER_INITIAL_JOBS)
            + tuple("ordinary-delivery-" + role for role in ROLES)
            + tuple("ordinary-generation-" + role for role in ROLES)
            + tuple("native-delivery-" + role for role in endpoints[3:])
            + key_names + native_names + transition_names + launch_names
            + tuple("install-launch-" + role for role in endpoints) + ("service-material",))
        self.assertEqual(tuple(job.name for job in execution.JOBS[phase]), service_names)
        self.assertEqual(supervisor.SUPPORTED_JOBS[7:], tuple((phase, name) for name in service_names))
        self.assertEqual((len(supervisor.SUPPORTED_JOBS), len(supervisor._ORDER), len(supervisor.missing_jobs())), (142, 151, 9))
        with self.assertRaises(ValueError):
            supervisor.require_complete_coverage()

    def test_static_policy_is_closed_copied_and_not_future_observation(self):
        value, cold, driver = policy_fixture()
        checked = composer.validate_policy(value, ordinary_cold_originals=cold, driver_configuration=driver)
        self.assertEqual(checked, value)
        self.assertEqual(set(checked), {"apiVersion", "services"})
        self.assertEqual(len(checked["services"][ROLE]), 10)
        checked["services"][ROLE]["endpointGeneration"] += 1
        self.assertNotEqual(checked, value)
        # Sharing separately approved keys across rows is allowed; only each
        # row's three capabilities and excluded C9/driver keys must differ.
        self.assertEqual(value["services"][ROLES[0]]["authorities"], value["services"][ROLES[-1]]["authorities"])

    def test_v4_parser_widens_only_exact_positive_u64_counters(self):
        fragment, _, _ = policy_fixture()
        counters = ("endpointGeneration", "serviceGeneration", "operationGeneration",
            "durableEpoch", "revocationGenerationHighWater")
        maximum = (1 << 64) - 1
        for row in fragment["services"].values():
            for name in counters:
                row[name] = maximum
        # Parser skeleton only: full retained policy admission is not claimed.
        value = {"apiVersion": "serverware.nativePilotSupervisorCommissioningPolicy/v4",
            "ordinaryInitialHistories": fragment}
        before = copy.deepcopy(value)
        raw = canonical(value)
        parsed = policy._policy_document(raw)
        self.assertEqual(parsed, before)
        self.assertEqual(value, before)
        self.assertEqual(raw, canonical(before))
        parsed["ordinaryInitialHistories"]["services"][ROLE][counters[0]] = 1
        self.assertEqual(value, before)
        for mutation in ("overflow", "zero", "bool", "legacy", "non-counter"):
            changed = copy.deepcopy(before)
            if mutation in ("overflow", "zero", "bool"):
                changed["ordinaryInitialHistories"]["services"][ROLE][counters[0]] = {
                    "overflow": maximum + 1, "zero": 0, "bool": True}[mutation]
            elif mutation == "legacy":
                changed["apiVersion"] = "serverware.nativePilotSupervisorCommissioningPolicy/v3"
            else:
                changed["notAnInitialCounter"] = maximum
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                policy._policy_document(canonical(changed))
        duplicate = raw[:-1] + b',"apiVersion":"serverware.nativePilotSupervisorCommissioningPolicy/v4"}'
        for changed in (raw + b"\n", duplicate):
            with self.subTest(noncanonical=changed[-100:]), self.assertRaises(ValueError):
                policy._policy_document(changed)

    def test_policy_refuses_future_fields_unknown_profiles_and_reused_capabilities(self):
        for mutation in ("future", "unknown", "version", "missing", "shared-key", "validity", "endpoint-role"):
            value, cold, driver = policy_fixture()
            row = value["services"][ROLE]
            if mutation == "future":
                row["endpointProcessIdentitySha256"] = labelled("predicted-process")
            elif mutation == "unknown":
                value["permitFallback"] = True
            elif mutation == "version":
                value["apiVersion"] = "serverware.nativePilotSupervisorOrdinaryInitialPolicy/v2"
            elif mutation == "missing":
                del value["services"][ROLES[-1]]
            elif mutation == "shared-key":
                row["authorities"]["service"] = copy.deepcopy(row["authorities"]["checkpoint"])
            elif mutation == "validity":
                row["validity"] = "renew-at-every-job"
            else:
                row["endpointRole"] = "signer-hsm"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                composer.validate_policy(value, ordinary_cold_originals=cold, driver_configuration=driver)

    def test_checkpoint_output_matches_complete_approved_payload_and_original_hash(self):
        value, result, raw = stage_fixture("checkpoint")
        self.assertEqual(composer.checked_result(ROLE, "checkpoint", canonical(value), result), raw)
        for mutation in ("payload", "digest", "extra-result", "wrong-role"):
            v, r = copy.deepcopy(value), copy.deepcopy(result)
            role = ROLE
            if mutation == "payload":
                payload = json.loads(v["payloadOriginal"])
                payload["revocationRootSha256"] = labelled("different-approved-payload")
                v["payloadOriginal"] = canonical(payload).decode("ascii")
            elif mutation == "digest":
                r["sha256"] = labelled("not-output-original")
            elif mutation == "extra-result":
                r["ready"] = True
            else:
                role = ROLES[1]
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, InvalidSignature)):
                composer.checked_result(role, "checkpoint", canonical(v), r)

    def test_detached_signatures_bind_signer_and_actual_prior_checkpoint(self):
        for operation in ("root-anchor", "checkpoint-anchor", "service-anchor"):
            value, result, raw = stage_fixture(operation)
            with self.subTest(operation=operation):
                self.assertEqual(composer.checked_result(ROLE, operation, canonical(value), result), raw)
                changed = json.loads(result["original"])
                changed["anchorPayloadSha256"] = labelled("different-prior-checkpoint")
                altered = canonical(changed)
                with self.assertRaises((ValueError, InvalidSignature)):
                    composer.checked_result(ROLE, operation, canonical(value),
                        {"original": altered.decode("ascii"), "sha256": sha(altered)})
                changed = json.loads(result["original"])
                signature = base64.urlsafe_b64decode(changed["signatureBase64"] + "==")
                changed["signatureBase64"] = encoded(bytes([signature[0] ^ 1]) + signature[1:])
                altered = canonical(changed)
                with self.assertRaises(InvalidSignature):
                    composer.checked_result(ROLE, operation, canonical(value),
                        {"original": altered.decode("ascii"), "sha256": sha(altered)})
                changed = json.loads(result["original"])
                changed["signer"] = "service" if operation == "root-anchor" else "root"
                altered = canonical(changed)
                with self.assertRaises(ValueError):
                    composer.checked_result(ROLE, operation, canonical(value),
                        {"original": altered.decode("ascii"), "sha256": sha(altered)})

    def test_assembly_requires_exact_prior_signatures_and_fixed_publication_pin(self):
        value, result, raw = stage_fixture("assemble")
        self.assertEqual(composer.checked_result(ROLE, "assemble", canonical(value), result), raw)
        purpose = "ordinary-initial-history-" + ROLE
        # Shape/commitment checks are not a publication or signature verdict.
        publication.shape(purpose, raw)
        with self.assertRaises(ValueError):
            publication.shape("ordinary-initial-history-" + ROLES[1], raw)
        tampered = json.loads(raw)
        tampered["history"]["manifestSha256"] = labelled("wrong-semantic-manifest")
        with self.assertRaises(ValueError):
            publication.shape(purpose, canonical(tampered))
        for mutation in ("signature", "path", "pin-digest", "missing-prior"):
            v, r = copy.deepcopy(value), copy.deepcopy(result)
            if mutation == "signature":
                record = json.loads(v["anchorSignatures"]["root"])
                record["signatureBase64"] = encoded(b"X" * 64)
                v["anchorSignatures"]["root"] = canonical(record).decode("ascii")
            elif mutation == "path":
                r["pin"]["path"] = r["pin"]["path"].replace(ROLE, ROLES[1])
            elif mutation == "pin-digest":
                r["pin"]["sha256"] = labelled("not-retained-wrapper")
            else:
                del v["anchorSignatures"]["checkpoint"]
            with self.subTest(mutation=mutation), self.assertRaises((ValueError, InvalidSignature)):
                composer.checked_result(ROLE, "assemble", canonical(v), r)

    def test_approval_serialization_preserves_request_deadline_and_input_binding(self):
        value, _, _ = stage_fixture("checkpoint")
        input_raw = canonical(value)
        request = {"apiVersion": "serverware.nativePilotAuthorityJobRequest/v1", "sequence": 8,
            "conductorSequence": 5, "conductorRequestSha256": labelled("synthetic-conductor-request"),
            "phase": "service-originals", "jobIndex": 1, "job": "ordinary-initial-checkpoint-" + ROLE,
            "deadlineBoottimeNs": "5000", "conductorRequest": None,
            "previousResult": {"phase": "endpoint-deliveries", "job": "native-delivery-trustedTime", "result": {}}}
        # Pure serialization is intentionally not a live request/admission test.
        approval = json.loads(supervisor._approval(canonical(request), input_raw))
        self.assertEqual(approval, {"apiVersion": "serverware.nativePilotAuthorityJobApproval/v1",
            **{name: request[name] for name in ("conductorSequence", "conductorRequestSha256", "phase",
                "jobIndex", "job", "deadlineBoottimeNs")}, "inputSha256": sha(input_raw)})
        changed = dict(value); changed["payloadOriginal"] = "{}"
        second = json.loads(supervisor._approval(canonical(request), canonical(changed)))
        self.assertNotEqual(second["inputSha256"], approval["inputSha256"])
        self.assertEqual(second["deadlineBoottimeNs"], "5000")


if __name__ == "__main__":
    unittest.main(verbosity=2)
