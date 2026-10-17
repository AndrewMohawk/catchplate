#!/usr/bin/env python3
"""Synthetic genuine signatures/certificates, not signer runtime admission."""
import copy
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.authority import local_enrollment_configuration as cli
from scripts.test_authority_local_configuration import fixture as service_fixture, sealed
from scripts.test_authority_local_keys import synthetic_audit_inventory_original
from catchplate import authority_local_enrollment_configuration as local

PIN = "sha256:" + "1" * 64


def public_row(row, public):
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return dict(row, publicKeyBase64Url=local.spec.strict_base64url_encode(raw), publicKeySha256=local.sha(raw),
        publicKeySpkiSha256=local.sha(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))


def fixture():
    base, payload, root = service_fixture()
    payload["webauthn"].update(allowedAuthenticatorClasses=["hardware", "yubikey"], requireAttestationTrusted=True)
    payload["roles"]["planner"]["enabledOperations"] = ["policy.genesis.finalize", "policy.genesis.prepare", "webauthn.challenge.create"]
    rows, roster = [], {}
    for index, row in enumerate(local.keys.roster()):
        if row["family"] == "configuration": public = root.public_key()
        elif row["family"] == "service":
            public = local.Ed25519PublicKey.from_public_bytes(local.configuration._public(base["runtimePublicKeys"][row["purpose"]]))
        else: public = Ed25519PrivateKey.from_private_bytes(bytes([100 + index]) * 32).public_key()
        entry = public_row(row, public)
        rows.append(entry)
        if row["family"] == "artifact": roster[row["purpose"]] = entry["publicKeyBase64Url"]
    pilot = local.canonical(dict(schema=local.keys.INVENTORY_SCHEMA, approvalSha256=PIN,
        directory=dict(device=1, inode=2), publicRosterSha256=local.sha(local.canonical(roster)), keys=rows, claims=local.keys.CLAIMS))
    audit = synthetic_audit_inventory_original(pilot)
    audit_value = local.document(audit, local.keys.MAX_PUBLIC)
    payload["policyGenesis"] = dict(auditStoreIdentityDigest=PIN, auditSignerPublicKeyDigest=audit_value["keys"][0]["publicKeySpkiSha256"])
    added = [public_row(row, Ed25519PrivateKey.from_private_bytes(bytes([22 + index]) * 32).public_key())
        for index, row in enumerate(local.keys.enrollment_roster())]
    enrollment = local.canonical(dict(schema=local.keys.ENROLLMENT_INVENTORY_SCHEMA, approvalSha256=PIN,
        directory=dict(device=1, inode=4), publicRosterSha256=local.sha(local.canonical({row["purpose"]: row["publicKeyBase64Url"] for row in added})),
        keys=added, claims=local.keys.CLAIMS, pilotKeyInventorySha256=local.sha(pilot), genesisAuditKeyInventorySha256=local.sha(audit)))
    now = time.time_ns()
    claims = dict(schema=local.signer.ATTESTATION_PAYLOAD_SCHEMA, sourceRevision=local.signer.authority.SOURCE_REVISION,
        role=local.signer.ROLE, processMode=local.signer.PROCESS_MODE, sessionIdentityDigest=PIN,
        measurementDigest=PIN, runtimeClosureDigest=PIN, signingSpkiDigest=added[1]["publicKeySpkiSha256"],
        issuedAtEpochNs=now - 1_000_000_000, expiresAtEpochNs=now + 240_000_000_000,
        trustMode="trusted-host-local", coLocated=True, hardwareBacked=False, nativeStageZero=False,
        hsmBackedKeys=False, teeVerified=False, externalWitnessVerified=False)
    receipt = local.signer._produce_attestation_on_work(claims=claims, root_private_key=root,
        root_public_key=root.public_key(), work=local._ValidationWork(local.QueryReadValidationLimits()))
    payload_raw = local.canonical(payload)
    base.update(payloadOriginal=payload_raw.decode("ascii"), payloadSha256=local.sha(payload_raw))
    base_raw = local.canonical(base)
    selected = dict(schema=local.SCHEMA, purpose=local.PURPOSE,
        configurationApprovalOriginal=base_raw.decode("ascii"), configurationApprovalSha256=local.sha(base_raw),
        pilotKeyInventoryOriginal=pilot.decode("ascii"), genesisAuditKeyInventoryOriginal=audit.decode("ascii"),
        enrollmentKeyInventoryOriginal=enrollment.decode("ascii"), registrationSignerAttestationOriginal=receipt.decode("ascii"),
        registrationSignerAttestationSha256=local.sha(receipt), issuerId="synthetic-local-enrollment", maximumAgeNs=10_000_000_000,
        maximumClockSkewNs=1_000_000_000, maximumPlanAgeNs=10_000_000_000, attestationMaximumAgeNs=300_000_000_000)
    return selected, base, payload, root


def prepare(selected):
    return local.prepare(local.canonical(selected), boot=local.configuration.launcher._boot_identity_digest(),
        now_boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME), now_unix_ns=time.time_ns())


class EnrollmentConfigurationTests(unittest.TestCase):
    def test_actual_signed_local_identity_projects_only_existing_three_policies_and_two_operations(self):
        selected, base, before, _ = fixture()
        result = prepare(selected)
        after = local.document(result["configurationApprovalOriginal"], local.io.MAX_PUBLIC)
        payload = local.document(after["payloadOriginal"].encode("ascii"), local.configuration.MAX_CONFIGURATION)
        self.assertEqual({name: value for name, value in after.items() if name not in ("payloadOriginal", "payloadSha256")},
            {name: value for name, value in base.items() if name not in ("payloadOriginal", "payloadSha256")})
        policies = (local.evidence.FIELD, local.transition.FIELD, local.enrollment.FIELD)
        stripped = copy.deepcopy(payload)
        for field in policies: stripped.pop(field)
        stripped["roles"]["planner"]["enabledOperations"] = before["roles"]["planner"]["enabledOperations"]
        self.assertEqual(stripped, before)
        evidence = payload[local.evidence.FIELD]["registration"]
        self.assertEqual(evidence["signerIdentity"], payload[local.transition.FIELD]["registration"]["signerIdentity"])
        self.assertEqual(evidence["signingSpkiDigest"], payload[local.enrollment.FIELD]["audienceSigningSpkiDigest"])
        self.assertNotEqual(evidence["signingSpkiDigest"], payload[local.enrollment.FIELD]["signingSpkiDigest"])
        self.assertIsNone(payload[local.evidence.FIELD]["installation"])
        self.assertIsNone(payload[local.transition.FIELD]["stage"])
        self.assertIsNone(payload[local.transition.FIELD]["completion"])
        self.assertEqual(result["deadline"], base["deadlineBoottimeNs"])

    def test_wrong_root_signature_and_unrelated_signer_public_identity_refuse(self):
        selected, _, _, root = fixture()
        for mode in ("signature", "key"):
            changed = copy.deepcopy(selected)
            receipt = local.document(changed["registrationSignerAttestationOriginal"].encode("ascii"), local.signer.MAX_ATTESTATION_BYTES)
            if mode == "signature": receipt["signatureBase64Url"] = local.spec.strict_base64url_encode(b"x" * 64)
            else: receipt["payload"]["signingSpkiDigest"] = PIN
            raw = (local.canonical(receipt) if mode == "signature" else
                local.signer._produce_attestation_on_work(claims=receipt["payload"], root_private_key=root,
                    root_public_key=root.public_key(), work=local._ValidationWork(local.QueryReadValidationLimits())))
            changed.update(registrationSignerAttestationOriginal=raw.decode("ascii"), registrationSignerAttestationSha256=local.sha(raw))
            with self.assertRaises((ValueError, InvalidSignature)): prepare(changed)

    def test_prior_inventory_pins_and_nonhardware_policy_cannot_be_substituted(self):
        selected, _, _, _ = fixture()
        changed = copy.deepcopy(selected)
        inventory = local.document(changed["enrollmentKeyInventoryOriginal"].encode("ascii"), local.keys.MAX_PUBLIC)
        inventory["genesisAuditKeyInventorySha256"] = PIN
        changed["enrollmentKeyInventoryOriginal"] = local.canonical(inventory).decode("ascii")
        with self.assertRaises(ValueError): prepare(changed)
        changed = copy.deepcopy(selected)
        base = local.document(changed["configurationApprovalOriginal"].encode("ascii"), local.io.MAX_PUBLIC)
        payload = local.document(base["payloadOriginal"].encode("ascii"), local.configuration.MAX_CONFIGURATION)
        payload["webauthn"]["requireAttestationTrusted"] = False
        raw = local.canonical(payload); base.update(payloadOriginal=raw.decode("ascii"), payloadSha256=local.sha(raw))
        raw = local.canonical(base); changed.update(configurationApprovalOriginal=raw.decode("ascii"), configurationApprovalSha256=local.sha(raw))
        with self.assertRaises(ValueError): prepare(changed)

    def test_signed_expiry_cannot_be_hidden_by_a_broader_original_configuration_window(self):
        selected, _, _, root = fixture()
        receipt = local.document(selected["registrationSignerAttestationOriginal"].encode("ascii"), local.signer.MAX_ATTESTATION_BYTES)
        receipt["payload"]["expiresAtEpochNs"] = time.time_ns() + 5_000_000_000
        raw = local.signer._produce_attestation_on_work(claims=receipt["payload"], root_private_key=root,
            root_public_key=root.public_key(), work=local._ValidationWork(local.QueryReadValidationLimits()))
        selected.update(registrationSignerAttestationOriginal=raw.decode("ascii"), registrationSignerAttestationSha256=local.sha(raw))
        with self.assertRaises(ValueError): prepare(selected)

    def test_already_enabled_policy_cannot_be_replaced_or_reapproved(self):
        selected, _, _, _ = fixture()
        result = prepare(selected)
        raw = result["configurationApprovalOriginal"]
        selected.update(configurationApprovalOriginal=raw.decode("ascii"), configurationApprovalSha256=local.sha(raw))
        with self.assertRaises(ValueError): prepare(selected)

    @unittest.skipUnless(os.getresuid() == os.getresgid() == (0, 0, 0) and sys.flags.isolated and sys.flags.dont_write_bytecode,
        "actual public FD owner requires isolated root -I -B")
    def test_actual_protected_fd_owner_builds_exact_unsigned_existing_approval_once(self):
        selected, _, _, _ = fixture()
        raw = local.canonical(selected)
        fd = sealed(raw)
        try:
            with patch.dict(os.environ, {"CATCHPLATE_RELEASE_CHANNEL": "dev", "CATCHPLATE_PROCESS_MODE": "metadata-bootstrap"}):
                owner = local.LocalEnrollmentConfigurationBuilder(approval_fd=fd, approval_sha256=local.sha(raw))
                output = owner.build()
                self.assertEqual(local.document(output, local.io.MAX_PUBLIC)["schema"], local.configuration.SCHEMA)
                self.assertEqual(output, prepare(selected)["configurationApprovalOriginal"])
                owner.check()
                with self.assertRaises(ValueError): owner.build()
                os.fstat(fd)  # Borrowed descriptor remains actual caller-owned material.
        finally: os.close(fd)

    def test_closed_cli_has_no_signing_key_path_or_live_attestation_override(self):
        arguments = ["--approval-fd", "3", "--approval-sha256", PIN]
        self.assertEqual(cli.arguments(arguments), dict(approval_fd=3, approval_sha256=PIN))
        for wrong in (arguments + ["--signing-key-fd", "4"], [arguments[0], "03", *arguments[2:]], arguments[:-1] + ["bad"]):
            with self.assertRaises(ValueError): cli.arguments(wrong)


if __name__ == "__main__":
    unittest.main()
