#!/usr/bin/env python3
"""Bounded pure policy/projection controls, not commissioning acceptance.

Keys, the self-signed CA, signed startup receipt and public contexts are TEST
fixtures only. No certificate/receipt is deployment evidence. Projection tests
deliberately do not claim authenticated build() acceptance for eleven complete
retained-history transcripts. No owner or issuer entrypoint is invoked.
"""
from __future__ import annotations

import copy
import datetime
import json
from pathlib import Path
import sys
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS.parent))
from serverware import native_pilot_native_service_profile as profile
from serverware import native_pilot_generation_install_authority as installation
from test_native_pilot_closure_set import canonical, frame, sha, synthetic
from test_native_pilot_generation_scope import NOW, key_fixture, trust_key
from test_native_pilot_history_grants import common, generation_payload
from test_native_pilot_runtime_evidence import fixture as evidence_fixture

ROLES = ("retrieval", "persistence", "trustedTime", "generationInstall", "commitRequest",
    "ingressAdmission", "terminalAppend", "dispatchBarrier", "activeEffectBarrier", "activeEffectCommit")
OPERATIONS = ("commitRequest", "ingress", "ledger", "terminal", "dispatchBarrier", "activeEffectBarrier",
    "activeEffectCommit", "retrieval", "persistence", "trustedTime", "generationInstall")
FIELDS = ("apiVersion", "verifierSettings", "operationWindows", "spool", "commitment", "persistence", "trustedTime", "generationInstall")


def fixture():
    """A closed independent policy, not evidence of a real Nitro execution."""
    key = key_fixture("SYNTHETIC-NITRO-POLICY-CA-NOT-AWS")[0]
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic policy test CA only")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, algorithm=None))
    certificate_raw = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    pcrs = {"PCR" + str(index): "sha384:" + str(index + 1) * 96 for index in range(3)}
    nitro = {"expectedPcrs": pcrs, "expectedEif": pcrs["PCR0"], "expectedModuleId": "synthetic-module-not-an-enclave",
        "awsNitroRootCertificatesPem": [certificate_raw], "nitroCertificateProfile": {
            "profileId": "aws-nitro-attestation-pki-native-v1", "allowedLeafExtendedKeyUsageOids": []},
        "maxAgeSeconds": 30, "futureSkewSeconds": 1}
    revocation = {"apiVersion": "serverware.nativeShadowNitroApplicationRevocation/v1",
        "profile": "application-denial-inventory-no-vendor-crl-v1", "generation": 1,
        "issuedAtUnixNanos": NOW - 1_000_000_000, "expiresAtUnixNanos": NOW + 1_000_000_000,
        "deniedCertificateSha256s": []}
    row = {"uid": 63000, "gid": 63000, "nitro": nitro, "collateralRevocation": revocation,
        "expectedAttestation": {"platform": "aws-nitro-enclave", "expectedMeasurementSha256": synthetic("unexecuted-expected-measurement"),
            "endorsementRootSha256": sha(certificate.public_bytes(serialization.Encoding.DER)),
            "collateralPolicySha256": frame("serverware.nativeShadowNitroCollateralPolicy/v1", nitro),
            "revocationSourceSha256": sha(canonical(revocation))}, "maximumResultAgeNanos": 30_000_000_000}
    return {"apiVersion": "serverware.nativePilotNativeServicePolicy/v1",
        "verifierSettings": {role: copy.deepcopy(row) | {"uid": 63000 + i, "gid": 63000 + i} for i, role in enumerate(ROLES)},
        "operationWindows": {operation: {"issuedAtUnixNanos": NOW - 500_000_000,
            "expiresAtUnixNanos": NOW + 500_000_000} for operation in OPERATIONS},
        "spool": {"generationId": synthetic("independently-selected-generation"),
            "originVerifier": trust_key(key_fixture("independent-origin-verifier")[1])},
        "commitment": evidence_fixture()["fragment"],
        "persistence": {"initialization": "fresh-persistence", "permissions": ["store-dispatch-original", "verify-persistence"]},
        "trustedTime": {"parentPort": 10444, "maximumBracketNanos": "1000000", "timestampErrorNanos": 1000,
            "maximumClockRateErrorPpm": 10}, "generationInstall": {"initialization": "fresh-generation",
                "keyHistory": {"currentKeyEpoch": 1, "predecessors": []}, "recordOriginals": []}}


class NativeServicePolicyTests(unittest.TestCase):
    def test_completed_persistence_requires_explicit_policy_and_exact_permission_order(self):
        selected = fixture(); selected["apiVersion"] = profile.COMPLETED_API
        selected["persistence"]["permissions"] = list(profile.authority.persistence.COMPLETED_PERMISSIONS)
        self.assertEqual(profile.validate_policy(selected), selected)
        for api, permissions in ((fixture()["apiVersion"], selected["persistence"]["permissions"]),
                (profile.COMPLETED_API, ["store-dispatch-original", "verify-persistence"]),
                (profile.COMPLETED_API, list(reversed(selected["persistence"]["permissions"]))),
                (profile.COMPLETED_API, selected["persistence"]["permissions"] + ["unknown"])):
            value = copy.deepcopy(selected); value["apiVersion"] = api
            value["persistence"]["permissions"] = permissions
            with self.subTest(api=api, permissions=permissions), self.assertRaises(ValueError):
                profile.validate_policy(value)

    def test_closed_eight_field_policy_ten_verifiers_eleven_windows(self):
        value = fixture()
        checked = profile.validate_policy(value)
        self.assertEqual(checked, value)
        self.assertEqual(set(checked), set(FIELDS))
        self.assertEqual(set(checked["verifierSettings"]), set(ROLES))
        self.assertEqual(tuple(profile.OPERATIONS), OPERATIONS)
        expected = {operation: operation for operation in OPERATIONS}
        expected.update(ingress="ingressAdmission", ledger="commitRequest", terminal="terminalAppend")
        self.assertEqual(profile.ENDPOINT_ROLES, expected)
        checked["trustedTime"]["parentPort"] = 12345
        self.assertNotEqual(checked, value)

    def test_missing_unknown_and_mixed_policy_maps_rejected(self):
        base = fixture()
        for name in FIELDS:
            value = copy.deepcopy(base); del value[name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                profile.validate_policy(value)
        for field, key in (("verifierSettings", "bridge"), ("operationWindows", "ordinary-generation")):
            value = copy.deepcopy(base); value[field][key] = {}
            with self.assertRaises(ValueError):
                profile.validate_policy(value)
        for api in (None, "serverware.nativePilotNativeServicePolicy/v2"):
            value = copy.deepcopy(base); value["apiVersion"] = api
            with self.assertRaises(ValueError):
                profile.validate_policy(value)

    def test_verifier_expectations_bind_actual_selected_policy_originals(self):
        base = fixture()["verifierSettings"]["commitRequest"]
        profile._verifier(base, now=NOW)
        for name in ("endorsementRootSha256", "collateralPolicySha256", "revocationSourceSha256"):
            value = copy.deepcopy(base); value["expectedAttestation"][name] = synthetic("different-" + name)
            with self.assertRaises(ValueError):
                profile._verifier(value, now=NOW)
        for field, value in (("expectedEif", "sha384:" + "f" * 96), ("futureSkewSeconds", 31)):
            row = copy.deepcopy(base); row["nitro"][field] = value
            with self.assertRaises(ValueError):
                profile._verifier(row, now=NOW)
        for value in (True, 0, 30_000_000_001):
            row = copy.deepcopy(base); row["maximumResultAgeNanos"] = value
            with self.assertRaises(ValueError):
                profile._verifier(row, now=NOW)

    def test_revocation_currentness_is_rechecked_at_actual_supplied_clock(self):
        row = fixture()["verifierSettings"]["retrieval"]
        profile._verifier(row)  # Structural policy admission, not a live verdict.
        for now in (NOW - 1_000_000_001, NOW + 1_000_000_000, True):
            with self.assertRaises(ValueError):
                profile._verifier(row, now=now)

    def test_fresh_profiles_do_not_approve_history_or_permissions_by_default(self):
        base = fixture()
        cases = []
        for initialization in (None, "fresh", "restored-persistence"):
            value = copy.deepcopy(base); value["persistence"]["initialization"] = initialization; cases.append(value)
        for permissions in ([], ["verify-persistence", "store-dispatch-original"], ["write-anything"]):
            value = copy.deepcopy(base); value["persistence"]["permissions"] = permissions; cases.append(value)
        for name, bad in (("currentKeyEpoch", True), ("currentKeyEpoch", 2), ("predecessors", ["invented-history"])):
            value = copy.deepcopy(base); value["generationInstall"]["keyHistory"][name] = bad; cases.append(value)
        value = copy.deepcopy(base); value["generationInstall"]["recordOriginals"] = ["invented-record"]; cases.append(value)
        for value in cases:
            with self.assertRaises(ValueError):
                profile.validate_policy(value)

    def test_independent_windows_and_bootstrap_settings_are_not_synthesized(self):
        base = fixture()
        checked = profile.validate_policy(base)
        self.assertEqual(checked["operationWindows"], base["operationWindows"])
        for name, bad in (("issuedAtUnixNanos", True), ("expiresAtUnixNanos", NOW - 500_000_000)):
            value = copy.deepcopy(base); value["operationWindows"]["ledger"][name] = bad
            with self.assertRaises(ValueError):
                profile.validate_policy(value)
        for name, bad in (("parentPort", 1023), ("maximumBracketNanos", "1000000001"),
                ("timestampErrorNanos", -1), ("maximumClockRateErrorPpm", 10001), ("signingKeyId", synthetic("unapproved-key"))):
            value = copy.deepcopy(base); value["trustedTime"][name] = bad
            with self.assertRaises(ValueError):
                profile.validate_policy(value)

    def test_unsigned_fresh_generation_projection_binds_exact_public_rows(self):
        # Test only deterministic projection; these labelled rows are not a
        # retained authenticated _ordinary context and never enter build().
        payload, domain = generation_payload(successor=True)
        rows = payload["services"]
        selected = common()
        delivery = {name: canonical({"syntheticOriginal": name}).decode("ascii") for name in (
            "ownerConfigurationOriginal", "windowOriginal", "observationOriginal", "configurationOriginal", "runtimeOriginal")}
        context = {"common": selected, "guest": selected["guest"], "admitted": selected,
            "config_raw": canonical({"syntheticConfig": True}), "assignment": {"syntheticAssignment": True},
            "delivery": delivery, "delivery_original": canonical({"syntheticDelivery": True}).decode("ascii")}
        ordinary = {"launchOriginal": canonical({"independentOrdinaryInvocation": "2" * 32}).decode("ascii"),
            "services": {role: {"syntheticServiceOriginal": role} for role in rows}}
        fragment = {"generationInstall": {"initialization": "fresh-generation", "keyHistory": {"currentKeyEpoch": 1,
            "predecessors": []}, "recordOriginals": []}}
        value = profile._generation(context, ordinary, rows, {"syntheticPeer": True}, fragment)
        result = json.loads(value["payloadOriginal"])
        genesis_raw = value["genesisOriginal"].encode("ascii")
        self.assertEqual(installation.grant_shape(result), domain)
        self.assertEqual(json.loads(genesis_raw)["servicesSha256"], sha(canonical(rows)))
        self.assertEqual(result["journal"], {"genesisSha256": sha(genesis_raw), "sequence": 0, "headSha256": sha(genesis_raw)})
        self.assertEqual(value["ordinaryLaunchOriginal"], ordinary["launchOriginal"])
        self.assertEqual(value["recordOriginals"], [])

    def test_all_eleven_real_preparation_dispatches_refuse_incomplete_originals(self):
        for operation in OPERATIONS:
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                profile.prepare_input(operation, b"{}", boot=("unused", 1, 1), now_boottime_ns=1000, now_unix_ns=NOW)
        with self.assertRaises(ValueError):
            profile.prepare_input("arbitrary-operation", b"{}", boot=("unused", 1, 1), now_boottime_ns=1000, now_unix_ns=NOW)


if __name__ == "__main__":
    unittest.main()
