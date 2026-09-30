#!/usr/bin/env python3
"""Synthetic public-scope controls, never commissioning or provenance evidence.

All keys, process observations, image pins and policies are in-memory fixtures.
Assignment/bootstrap signatures and hash frames are real but test-only. No
owner, filesystem credential, signer entrypoint, service or network is used.
Unrelated assignment-policy fields retain the existing grammar fixture's empty
values; this does not claim complete native assignment/runtime admission.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import stat
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))
from serverware import native_pilot_closure_set as closure_set
from serverware import native_pilot_ordinary_generation_profile as profile
from test_native_pilot_closure_set import (EXPECTED_SCOPE_ROOTS, EXPECTED_SCOPE_VALUES, KEY_ROLES,
    assignment_fixture, canonical, frame, members_fixture, merkle_fixture, scope_fixture, sha, synthetic)

NOW = 1_000_000_000_000
ASSIGNMENT_DOMAIN = "serverware.policyShadowAssignment/v2"
BOOTSTRAP_DOMAIN = "serverware.nativeShadowBootstrapDriverAdmission.signature/v1"
OPERATIONS = ("recover-current-state", "verify-checkpoint-successor", "verify-current-checkpoint-head",
    "verify-observation-evidence", "prepare-generation-publication", "commit-generation-publication",
    "abort-generation-publication", "begin-ingress", "reserve-spool-append", "append-spool-event", "compact-spool",
    "commit-request", "append-active-effect-barrier", "commit-active-effect", "reconcile-active-effect",
    "append-terminal", "consume-and-publish-activation")


def encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def signed_message(domain, payload):
    return (b"serverware.signedEnvelope/v1\0" + domain.encode("ascii")
        + b"\0serverware.canonicalJson/ascii-integer-v1\0" + canonical(payload))


def key_fixture(label):
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        ("SYNTHETIC GENERATION SCOPE TEST ONLY / " + label).encode("ascii")).digest())
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    material = sha(b"serverware.policyAuthorityPublicKeyMaterial/v1\0"
        + (7).to_bytes(8, "big") + b"ed25519" + len(spki).to_bytes(8, "big") + spki)
    return key, {"keyId": sha(spki), "keySpkiSha256": sha(spki), "keyMaterialSha256": material,
        "publicKeyBase64url": encoded(raw)}


def trust_key(public):
    return {name: public[name] for name in ("keyId", "keySpkiSha256", "publicKeyBase64url")} | {
        "notBeforeUnixNanos": NOW - 20_000_000_000, "notAfterUnixNanos": NOW + 90_000_000_000}


def fixture():
    """Complete inputs for the pure helper, with independently framed outputs."""
    selected_raw = closure_set.set_original(members_fixture())
    selected = json.loads(selected_raw)
    envelope = assignment_fixture(selected)
    assignment = envelope["payload"]
    keys = {role: key_fixture(role) for role in KEY_ROLES}
    rows = assignment["authorityKeyIndependence"]["bindings"]
    for row in rows:
        public = keys[row["role"]][1]
        row.update({name: public[name] for name in ("keyId", "keySpkiSha256", "keyMaterialSha256")})
        if row["role"].startswith("custody-"):
            parts = row["role"].removeprefix("custody-").split("-")
            prefix = parts[0] + "".join(part.title() for part in parts[1:])
            for suffix in ("KeyId", "KeySpkiSha256"):
                assignment["custodyAuthority"][prefix + suffix] = public[suffix[0].lower() + suffix[1:]]
    independence = assignment["authorityKeyIndependence"]
    for name, root in (("keyId", "keyIdSetRootSha256"), ("keySpkiSha256", "spkiSetRootSha256"),
            ("keyMaterialSha256", "keyMaterialSetRootSha256")):
        independence[root] = merkle_fixture(sorted(row[name] for row in rows))
    independence["independenceRootSha256"] = frame("serverware.policyAuthorityKeyIndependence/v1",
        [rows, independence["keyIdSetRootSha256"], independence["spkiSetRootSha256"], independence["keyMaterialSetRootSha256"]])
    assignment.update(issuedAtUnixNanos=NOW - 10_000_000_000, expiresAtUnixNanos=NOW + 60_000_000_000,
        observationWindow={"maximumEvidenceAgeNanos": 60_000_000_000})
    signing, signing_public = key_fixture("assignment")
    envelope.update(payloadSha256=sha(canonical(assignment)), signingKeyId=signing_public["keyId"],
        signingKeySpkiSha256=signing_public["keySpkiSha256"],
        signature=encoded(signing.sign(signed_message(ASSIGNMENT_DOMAIN, assignment))))
    trust = {"apiVersion": "serverware.nativeShadowGuestTrust/v1", "checkpoint": {
        "checkpointId": synthetic("trust-checkpoint"), "asOfUnixNanos": NOW - 10_000_000_000,
        "revocationGeneration": 1, "revocationRootSha256": synthetic("trust-revocation")},
        "assignmentKey": trust_key(signing_public), "timeKey": trust_key(key_fixture("time")[1]),
        "roleKeys": [{"role": role, "key": trust_key(keys[role][1])} for role in KEY_ROLES[7:]],
        "issuedAtUnixNanos": NOW - 10_000_000_000, "expiresAtUnixNanos": NOW + 60_000_000_000}
    bridge = selected["members"][-1]["manifest"]
    boot_key, phase_key = key_fixture("window")[1], key_fixture("phase")[1]
    def cold_key(public):
        raw = base64.urlsafe_b64decode(public["publicKeyBase64url"] + "==")
        return {"publicKeyBase64url": encoded(raw), "keyId": sha(raw)}
    image = {name: synthetic("bootstrap-image/" + name) for name in ("imageSha256", "executableSha256",
        "bootstrapRuntimeSha256", "dependencyLockSha256", "buildRecipeSha256", "provenanceSha256")}
    image.update(imageSha256=bridge["imageSha256"], executableSha256=bridge["workerExecutableSha256"],
        seccompPolicy=copy.deepcopy(bridge["seccompPolicy"]))
    transport = {"apiVersion": "serverware.nativeShadowKeyKmsTransport/v1", "kmsParentPort": 10443,
        "kmsKeyId": "synthetic-test-kms-key-not-provisioned", "ciphertextBlobSha256": synthetic("ciphertext"),
        "encryptionContext": {"serverwarePurpose": "native-shadow-local-role-keys/v1"},
        "kekSha256": synthetic("kek"), "encryptedInventorySha256": synthetic("inventory"),
        "helperImage": {"profile": "sealed-memfd-squashfs-v1",
            "imagePath": "/opt/serverware/native-shadow-key-delivery-runtime.squashfs",
            **{name: synthetic("helper/" + name) for name in ("imageSha256", "interpreterSha256", "helperSha256")}}}
    configuration = {"apiVersion": "serverware.nativeShadowDriverBootstrapConfiguration/v4",
        "bootstrapAuthority": cold_key(boot_key), "phaseTwoAuthority": cold_key(phase_key),
        "deliveryConfiguration": {"path": "/etc/serverware/synthetic-bridge-cold.json", "sha256": synthetic("cold")},
        "uid": 61000, "gid": 61000, "image": image,
        "continuation": {"apiVersion": "serverware.nativeShadowDriverContinuationPreparation/v3", "keyTransport": transport},
        "lifecycle": {"apiVersion": "serverware.nativeShadowDriverLifecyclePolicy/v3", "cleanupReserveNanos": 1000000,
            "gate": {"uid": 65534, "gid": 65534, "executableSha256": synthetic("gate")},
            "constructedAdmissionAuthority": keys["custody-supervisor-capability"][1]}}
    configuration_raw = canonical(configuration)
    invocation, boot_sha = "1" * 32, sha(b"synthetic-boot16")
    descriptors = [{"name": name, "device": 1, "inode": index + 101,
        "mode": stat.S_IFDIR | 0o700 if name in ("cgroup", "root") else stat.S_IFREG | 0o400,
        "mountId": 2} for index, name in enumerate(("self-pidfd", "executable", "cgroup", "root"))]
    driver = {"driverInstanceSha256": sha(canonical([invocation, 43, 100, descriptors[0]["inode"]])),
        "driverExecutableSha256": image["executableSha256"], "supervisorBootIdSha256": boot_sha,
        "processStartTimeTicks": 100, "pidfdInode": descriptors[0]["inode"], "cgroupId": 3,
        "cgroupMountId": 2, "cgroupInode": descriptors[2]["inode"],
        "retainedDescriptorManifestSha256": sha(canonical(descriptors)), "verifiedAtBoottimeNanos": 1000}
    driver["identitySha256"] = frame("serverware.policyShadowCustodyKernelDriverIdentity/v1", list(driver.values()))
    observation = {"apiVersion": "serverware.nativeShadowDriverObservation/v1", "configurationSha256": sha(configuration_raw),
        "windowSha256": synthetic("original-window"), "invocationId": invocation, "processId": 43,
        "uid": 61000, "gid": 61000, "cgroupOriginalSha256": synthetic("cgroup-original"),
        "root": descriptors[-1], "seccompFilterCount": 1, "descriptors": descriptors, "driver": driver}
    parent = {"processId": 42, "startTimeTicks": 99, "parentId": 2, "pidfdDevice": 0, "pidfdInode": 77}
    early = {"apiVersion": "serverware.nativeShadowBootstrapDriverAdmission/v1", "purpose": "native-driver-bootstrap-admission",
        "configurationSha256": sha(configuration_raw), "windowSha256": observation["windowSha256"],
        "bootstrapObservationOriginal": canonical(observation).decode("ascii"), "parent": parent,
        "parentExecutableSha256": synthetic("parent-executable"), "pidNamespaceSha256": synthetic("pid-namespace"),
        "issuedAtUnixNanos": NOW - 5_000_000_000, "expiresAtUnixNanos": NOW + 20_000_000_000,
        "startupDeadlineBoottimeNs": "2000000000", "lifetimeDeadlineBoottimeNs": "60000000000",
        "signingKeyId": keys["custody-supervisor-capability"][1]["keyId"],
        "signingKeySpkiSha256": keys["custody-supervisor-capability"][1]["keySpkiSha256"]}
    bootstrap = canonical({"payload": early, "signature": encoded(keys["custody-supervisor-capability"][0].sign(
        signed_message(BOOTSTRAP_DOMAIN, early)))})
    production = {name: synthetic(name) for name in ("signerBackendSha256", "persistenceBackendSha256",
        "retrievalBackendSha256", "dispatcherProtocolSetSha256")}
    production.update(maximumRpcNanos=250_000_000, cleanupReserveNanos=1_000_000,
        maximumInFlightCalls=1, maximumAsyncDurabilityNanos=1_000_000)
    scope = scope_fixture(envelope)
    authority = assignment["custodyAuthority"]
    coverage = frame("serverware.policyShadowCustodyOperationCoverage/v1", OPERATIONS)
    instance = sha(invocation.encode("ascii"))
    binding = {"assignmentId": assignment["assignmentId"], "assignmentPayloadSha256": envelope["payloadSha256"],
        "assignmentRevision": assignment["assignmentRevision"],
        **{name: authority[name] for name in ("authorityId", "storageRealmSha256", "retrievalNamespaceSha256", "attestationMode")},
        "authorityKeyIndependenceSha256": independence["independenceRootSha256"],
        "supervisorInstanceSha256": instance, "supervisorBootIdSha256": boot_sha,
        "executionClosureManifestSha256": bridge["manifestSha256"],
        "structurallyVerifiedSeccompPolicySha256": bridge["seccompPolicy"]["structurallyVerifiedPolicySha256"],
        "workerExecutableSha256": bridge["workerExecutableSha256"], **production,
        "operationCoverageRootSha256": coverage, "kernelRetainedDriverIdentitySha256": driver["identitySha256"],
        "assertedCustodyKeySetRootSha256": scope["asserted_custody_key_set_root_sha256"],
        "nativeClosureSet": copy.deepcopy(assignment["nativeClosureSet"])}
    binding_sha = frame("serverware.policyShadowProductionCustodyConfiguration/v2", binding)
    scope["production_configuration_binding_sha256"] = binding_sha
    scope["binding_sha256"] = frame("serverware.policyShadowProductionCustodyProofScope/v2",
        [scope[name] for name in EXPECTED_SCOPE_VALUES + EXPECTED_SCOPE_ROOTS])
    reaper = {"reaperInstanceSha256": frame("serverware.nativeShadowStableParentInstance/v1", [parent, instance]),
        "reaperExecutableSha256": early["parentExecutableSha256"], "supervisorInstanceSha256": instance,
        "supervisorBootIdSha256": boot_sha, "kernelDriverIdentitySha256": driver["identitySha256"],
        "subreaperProcessStartTimeTicks": 99, "pidfdNamespaceSha256": early["pidNamespaceSha256"],
        "retainedDescriptorSetSha256": driver["retainedDescriptorManifestSha256"], "ownershipEpoch": 99,
        "independentRestartForbidden": True}
    reaper["identitySha256"] = frame("serverware.policyShadowCustodyStableReaper/v1", list(reaper.values()))
    result_key = keys["custody-result-envelope"][1]
    dispatch = frame("serverware.policyShadowCustodyDispatchManifest/v1", ["serverware.policyShadowCustodyDispatch/v2",
        coverage, production["dispatcherProtocolSetSha256"], driver["identitySha256"], reaper["identitySha256"],
        driver["driverExecutableSha256"], production["signerBackendSha256"], production["persistenceBackendSha256"],
        production["retrievalBackendSha256"], 8 * 1024 * 1024, 8 * 1024 * 1024,
        production["maximumAsyncDurabilityNanos"], result_key["keyId"], result_key["keySpkiSha256"]])
    recipe = {"dispatchManifestSha256": dispatch, "driverGenerationReceiptSha256": sha(bootstrap),
        "kernelDriverIdentitySha256": driver["identitySha256"], "retainedDescriptorSetSha256": driver["retainedDescriptorManifestSha256"],
        "operationCoverageRootSha256": coverage, "stableReaperIdentity": reaper}
    fragment = {"apiVersion": "serverware.nativePilotOrdinaryGenerationPolicy/v1",
        "installationIssuedAtUnixNanos": NOW - 1_000_000_000, "installationExpiresAtUnixNanos": NOW + 1_000_000_000}
    arguments = {"measured": {"apiVersion": "serverware.nativePilotMeasuredConfiguration/v2", "recipeSha256": synthetic("recipe"),
        "configurationBindingOriginal": canonical(binding).decode("ascii"), "configurationBindingSha256": binding_sha,
        "proofScopeOriginal": canonical(scope).decode("ascii"),
        "production": {**production, "expectedConfigurationBindingSha256": binding_sha}},
        "recipe_originals": {"assignmentOriginal": canonical(envelope).decode("ascii"),
            "trustOriginal": canonical(trust).decode("ascii"), "trustSha256": sha(canonical(trust)),
            "closureSetOriginal": selected_raw.decode("ascii")},
        "driver_generation_recipe": recipe, "bootstrap_original": bootstrap,
        "bootstrap_configuration_original": configuration_raw, "driver_observation_original": canonical(observation),
        "now_unix_ns": NOW}
    expected = {"previousConfigurationBindingSha256": None, "successorConfigurationBindingSha256": binding_sha,
        **{name: value for name, value in recipe.items() if name != "stableReaperIdentity"},
        "assignmentId": assignment["assignmentId"], "assignmentPayloadSha256": envelope["payloadSha256"], "assignmentRevision": 1,
        "fiveServiceProtocolSetSha256": production["dispatcherProtocolSetSha256"],
        "envelopeAuthorityKeyId": result_key["keyId"], "envelopeAuthorityKeySpkiSha256": result_key["keySpkiSha256"],
        "trustedTimeCheckpointSha256": trust["checkpoint"]["checkpointId"], "trustedTimeRevocationGeneration": 1,
        "trustedTimeRevocationRootSha256": trust["checkpoint"]["revocationRootSha256"],
        **{name: fragment[name] for name in ("installationIssuedAtUnixNanos", "installationExpiresAtUnixNanos")}}
    return fragment, arguments, expected


class GenerationScopeControls(unittest.TestCase):
    def test_exact_positive_scope_uses_original_receipt_and_interval(self):
        fragment, args, expected = fixture()
        self.assertEqual(profile.derive_scope(fragment, **args), expected)
        self.assertEqual(len(expected), 18)
        self.assertEqual(expected["driverGenerationReceiptSha256"], sha(args["bootstrap_original"]))
        self.assertIsNone(expected["previousConfigurationBindingSha256"])

    def test_changed_driver_recipe_is_not_an_authority(self):
        for field in ("dispatchManifestSha256", "driverGenerationReceiptSha256", "retainedDescriptorSetSha256"):
            fragment, args, _ = fixture()
            args["driver_generation_recipe"][field] = synthetic("changed/" + field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                profile.derive_scope(fragment, **args)

    def test_real_assignment_and_bootstrap_signatures_are_required(self):
        for target in ("assignment", "bootstrap"):
            fragment, args, _ = fixture()
            raw = args["bootstrap_original"] if target == "bootstrap" else args["recipe_originals"]["assignmentOriginal"]
            value = json.loads(raw); value["signature"] = encoded(b"X" * 64)
            if target == "bootstrap":
                args["bootstrap_original"] = canonical(value)
            else:
                args["recipe_originals"]["assignmentOriginal"] = canonical(value).decode("ascii")
            with self.subTest(target=target), self.assertRaises(InvalidSignature):
                profile.derive_scope(fragment, **args)

    def test_original_interval_rejects_expiry_extension_and_nonintegers(self):
        for issued, expires in ((NOW, NOW), (NOW + 1, NOW + 2), (NOW - 1, NOW),
                (NOW - 1, NOW + 61_000_000_000), (True, NOW + 1), (NOW - 1, None)):
            fragment, args, _ = fixture()
            fragment.update(installationIssuedAtUnixNanos=issued, installationExpiresAtUnixNanos=expires)
            with self.subTest(issued=issued, expires=expires), self.assertRaises(ValueError):
                profile.derive_scope(fragment, **args)

    def test_pinned_trust_mismatch_and_key_interval_refuse(self):
        for target in ("pin", "key-window", "checkpoint-window"):
            fragment, args, _ = fixture()
            originals = args["recipe_originals"]
            trust = json.loads(originals["trustOriginal"])
            if target == "key-window":
                trust["roleKeys"][0]["key"]["notAfterUnixNanos"] = NOW + 1
            elif target == "checkpoint-window":
                trust["checkpoint"]["asOfUnixNanos"] = NOW
            else:
                trust["checkpoint"]["checkpointId"] = synthetic("changed-checkpoint")
            originals["trustOriginal"] = canonical(trust).decode("ascii")
            if target != "pin":
                originals["trustSha256"] = sha(canonical(trust))
            with self.subTest(target=target), self.assertRaises(ValueError):
                profile.derive_scope(fragment, **args)

    def test_measured_proof_and_closure_roots_cannot_be_substituted(self):
        for target in ("binding", "proof", "closure"):
            fragment, args, _ = fixture()
            if target == "binding":
                args["measured"]["configurationBindingSha256"] = synthetic("other-binding")
            elif target == "proof":
                value = json.loads(args["measured"]["proofScopeOriginal"])
                value["execution_closure_set_root_sha256"] = synthetic("other-set")
                args["measured"]["proofScopeOriginal"] = canonical(value).decode("ascii")
            else:
                value = json.loads(args["recipe_originals"]["closureSetOriginal"])
                value["seccompSetRootSha256"] = synthetic("other-seccomp-set")
                args["recipe_originals"]["closureSetOriginal"] = canonical(value).decode("ascii")
            with self.subTest(target=target), self.assertRaises(ValueError):
                profile.derive_scope(fragment, **args)


if __name__ == "__main__":
    unittest.main()
