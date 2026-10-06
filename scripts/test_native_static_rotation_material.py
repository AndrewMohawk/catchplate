#!/usr/bin/env python3
"""Focused local crypto/codec controls; not native custody or commit evidence."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from serverware import native_static_credential as creation
from serverware import native_static_credential_rotation as rotation


class RotationMaterial(unittest.TestCase):
    def setUp(self):
        self.key = AESGCM(bytes(range(32)))  # Public synthetic fixture, never deployed.
        self.kek_id = "attested-memory-kek:" + "a" * 24
        self.identifier = "12345678-1234-4234-8234-123456789abc"
        self.other_id = "12345678-1234-4234-8234-123456789abd"
        self.now = 1_791_273_600_123_456_000

    def seal(self, version=2, raw=b" username:password\n", module=rotation):
        return module.seal_original(self.identifier, raw, version, self.kek_id, self.key, self.now)

    def test_exact_successor_readback_and_fresh_entropy(self):
        left, right = self.seal(), self.seal()
        rotation.envelope_fields(left)
        self.assertEqual(rotation.open_original(self.identifier, left, 2, self.kek_id, self.key), b" username:password\n")
        self.assertNotEqual(left["encrypted_dek"], right["encrypted_dek"])
        self.assertNotEqual(left["secret_ciphertext"], right["secret_ciphertext"])

    def test_create_public_codec_remains_version_one_only(self):
        first = self.seal(version=1, module=creation)
        self.assertEqual(creation.open_original(self.identifier, first, 1, self.kek_id, self.key), b" username:password\n")
        with self.assertRaises(ValueError):
            creation.envelope_fields(self.seal())
        with self.assertRaises(ValueError):
            self.seal(version=2, module=creation)
        with self.assertRaises(ValueError):
            creation.open_original(self.identifier, self.seal(), 2, self.kek_id, self.key)
        with self.assertRaises(ValueError):
            rotation.envelope_fields(first)

    def test_rotation_refuses_non_successor_versions(self):
        for version in (None, False, True, 0, 1, -1, 2.0, "2", 2**63):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.seal(version=version)

    def test_large_integer_generation_not_float_coerced(self):
        version = 2**63 - 1
        envelope = self.seal(version=version)
        self.assertEqual(envelope["credential_version"], version)
        self.assertEqual(rotation.open_original(self.identifier, envelope, version, self.kek_id, self.key), b" username:password\n")

    def test_generation_and_identity_are_authenticated(self):
        envelope = self.seal()
        with self.assertRaises(InvalidTag):
            rotation.open_original(self.other_id, envelope, 2, self.kek_id, self.key)
        altered = copy.deepcopy(envelope)
        altered["credential_version"] = 3
        with self.assertRaises(InvalidTag):
            rotation.open_original(self.identifier, altered, 3, self.kek_id, self.key)
        with self.assertRaises(ValueError):
            rotation.open_original(self.identifier, envelope, 3, self.kek_id, self.key)

    def test_key_label_and_key_are_not_interchangeable(self):
        envelope = self.seal()
        with self.assertRaises(ValueError):
            rotation.open_original(self.identifier, envelope, 2, "attested-memory-kek:" + "b" * 24, self.key)
        with self.assertRaises(InvalidTag):
            rotation.open_original(self.identifier, envelope, 2, self.kek_id, AESGCM(bytes(reversed(range(32)))))

    def test_utf8_and_size_contract(self):
        for raw in (b"", b"\xff", b"x" * (rotation.MAX_SECRET_BYTES + 1), "password"):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                self.seal(raw=raw)
        raw = b"x" * rotation.MAX_SECRET_BYTES
        envelope = self.seal(raw=raw)
        self.assertEqual(rotation.open_original(self.identifier, envelope, 2, self.kek_id, self.key), raw)

    def test_closed_canonical_envelope(self):
        envelope = self.seal()
        for field, value in (("secret_nonce", envelope["secret_nonce"] + "="),
                ("secret_updated_at", "2026-10-06T00:00:00Z"),
                ("credential_version", True), ("extra", "field")):
            altered = {**envelope, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                rotation.envelope_fields(altered)


class RetainedRotationOwner(unittest.TestCase):
    """Local owner state machine only; the channel is explicitly synthetic."""
    def prepared(self, *, lose_reply=False):
        from scripts.test_authority_static_rotation import fixture, C, H, B
        from serverware import authority_static_credential_rotate as profile
        from serverware import native_static_credential_rotation_owner as native
        from serverware.native_oauth_refresh_owner import IDENTITY_FIELDS

        f = fixture()
        boot = 100_000_000_000

        class Channel:
            deadline = boot + 600_000_000_000
            def __init__(self): self.messages = []
            def check(self, deadline=None):
                if deadline is not None and not boot < deadline <= self.deadline:
                    raise ValueError("synthetic channel interval")
            def send(self, value, deadline=None):
                self.check(deadline)
                if lose_reply and value.get("phase") == "prepared":
                    raise OSError("synthetic lost output")
                self.messages.append(copy.deepcopy(value))

        class Broker:
            def __init__(self):
                self.channel, self.kek, self.key_id = Channel(), f["kek"], f["kek_id"]
                self.rsa, self.service_tokens_opened = None, True
            def require_owner_configuration(self): self.channel.check()

        self.addCleanup(patch.stopall)
        patch("serverware.native_static_credential_owner.time.time_ns", return_value=f["now"]).start()
        patch("serverware.native_static_credential_owner.time.clock_gettime_ns", return_value=boot).start()
        config = {"apiVersion": native.CONFIG, "controlPlaneConfigurationDigest": f["cfg"],
            profile.FIELD: {"schema": profile.SCHEMA, "credentialPolicy": f["policy"],
                "operationMaxSeconds": 30, "maximumArgumentBytes": profile.MAX_ARGUMENT_BYTES,
                "maximumSecretBytes": profile.MAX_SECRET_BYTES, "twoPersonRequired": False,
                "nativeSecretKekId": f["kek_id"], "intentMaxSeconds": 3600,
                "nativeCustodyPurpose": profile.NATIVE_CUSTODY_PURPOSE},
            "candidateCapacity": 1, "deploymentId": "fixture", "instanceId": "spiffe://fixture/native",
            "identity": {name: f["assignment_row"][name] for name in IDENTITY_FIELDS},
            "intakeOrigin": "https://intake.example", "portalOrigin": "https://unit.example",
            "ingressLeafCertificateSha256": H(b"synthetic leaf"), "ingressLeafSpkiSha256": H(b"synthetic spki")}
        broker = Broker()
        owner = native.Owner(broker, {"apiVersion": native.CHANNEL, "phase": "configure", "configuration": config})
        intent = profile.intent_original(actor_id=f["actor"], configuration_digest=f["cfg"],
            credential_policy=f["policy"], request=f["intent"]).decode("ascii")
        owner.handle({"apiVersion": native.CHANNEL, "phase": "intake", "intentOriginal": intent,
            "secretBase64url": B(b"private rotation input"), "deadlineBoottimeNs": boot + 30_000_000_000})
        retained = broker.channel.messages[-1]
        self.assertEqual(retained["phase"], "retained")
        self.assertNotIn("private rotation input", C(retained).decode())
        args = copy.deepcopy(f["values"])
        args["request"].update(nativeGenerationOriginal=retained["candidate"]["nativeGenerationOriginal"],
            executionIssuedAtEpochNs=f["now"], executionExpiresAtEpochNs=f["now"] + 10_000_000_000)
        command = {"apiVersion": native.CHANNEL, "phase": "prepare-execution", "credentialId": f["item"],
            "browserNonce": retained["browserNonce"], "argumentsOriginal": C(args).decode(),
            "challenge": B(b"n" * 32), "deadlineBoottimeNs": boot + 30_000_000_000}
        return owner, broker, command, args, f

    def test_original_retention_and_six_statement_bindings(self):
        from scripts.test_authority_static_rotation import H
        owner, broker, command, args, f = self.prepared()
        retained_deadline = owner._candidates[f["item"]].retention_deadline
        owner.handle(command)
        result = broker.channel.messages[-1]
        self.assertEqual(result["operation"], "credential.static.rotate")
        self.assertEqual(result["argumentsOriginal"], command["argumentsOriginal"])
        bindings = result["statementBindings"]
        for name in ("previousCredentialVersion", "previousCredentialSha256", "previousCurrentnessOriginRequestDigest",
                "predecessorBarrierSha256", "predecessorCurrentnessRootSha256"):
            self.assertEqual(bindings[name], args["request"][name])
        self.assertEqual(bindings["previousProvenanceSha256"], H(args["request"]["previousProvenanceOriginal"].encode()))
        self.assertEqual(bindings["credentialVersion"], 2)
        self.assertEqual(owner._candidates[f["item"]].retention_deadline, retained_deadline)
        with self.assertRaises(ValueError): owner.handle(command)

    def test_uncertain_prepare_is_spent_and_poisoned(self):
        owner, broker, command, args, f = self.prepared(lose_reply=True)
        with self.assertRaises(OSError): owner.handle(command)
        self.assertIn(f["item"], owner._spent)
        self.assertTrue(owner._poisoned)
        with self.assertRaises(ValueError): owner.handle(command)


if __name__ == "__main__":
    unittest.main()
