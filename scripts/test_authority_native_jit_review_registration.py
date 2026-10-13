#!/usr/bin/env python3
"""Optional JIT policy registration, not measured/native service admission.

The complete existing configuration fixture supplies synthetic root/role keys,
certificates and launch snapshots. The actual generator and signed service
loader run their signature, generation, topology and purpose-policy checks.
Only descriptor delivery and launch inputs are doubled. Service loading MUST
stop at an explicit runtime-closure refusal; no loaded configuration, active
launch, custody owner, database, provider or attestation success is supplied.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_external_violations = []


def no_external_effects(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {
        "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
    }:
        _external_violations.append(event)
        raise AssertionError("registration controls forbid external effects")


if __name__ == "__main__":
    os.environ["SERVERWARE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
    sys.addaudithook(no_external_effects)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from scripts import test_authority_local_configuration as configuration_fixture
from scripts import test_authority_native_jit_review_custody as custody_fixture
from scripts.authority import generate_artifact_bundle as generator
from serverware import authority_service as service

FIELD = "nativeJitReviewCustodyPolicy"
PAYLOAD_SCHEMA = "serverware.policyAuthorityServiceConfiguration/v6"
ENVELOPE_SCHEMA = "serverware.signedPolicyAuthorityServiceConfiguration/v6"


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def framed(domain, raw):
    return sha(domain.encode("ascii") + b"\0" + len(raw).to_bytes(8, "big") + raw)


class RuntimeAdmissionRefused(Exception):
    """Terminal test boundary, never a successful native admission verdict."""


class NativeJitRegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.selected, cls.original_payload, cls.root = configuration_fixture.fixture()
        cls.policy = custody_fixture.Fixture(custody_fixture.SyntheticNitro()).policy

    def setUp(self):
        self.payload = copy.deepcopy(self.original_payload)
        self.boundary_payloads = []
        self.descriptor_reads = []

    def tearDown(self):
        self.assertEqual(_external_violations, [], "negative tests must not swallow attempted external I/O")

    def with_policy(self):
        self.payload[FIELD] = copy.deepcopy(self.policy)
        return self.payload

    def generate(self, payload):
        spec = configuration_fixture.local.spec
        return generator.validate_configuration_payload(payload, role="authority-service",
            source_revision=generator.authority_contract.SOURCE_REVISION,
            expected_generation_binding=spec.configuration_generation_binding(self.selected["generation"]),
            expected_generation_binding_digest=spec.configuration_generation_binding_digest(self.selected["generation"]),
            expected_role_bindings=spec.role_binding_digests(self.selected["roleManifests"]),
            root_key=self.root.public_key())

    def load(self, payload, *, bad_signature=False, generation_change=None,
            forbid_launch=False):
        # Independently frame the real configuration signature, not the helper
        # whose registration is under test. These are test keys, not admission.
        signature = self.root.sign(framed(ENVELOPE_SCHEMA, canonical(payload)).encode("ascii"))
        if bad_signature:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        envelope = {"schema": ENVELOPE_SCHEMA, "payload": payload,
            "signature": custody_fixture.encoded(signature)}
        raw = canonical(envelope)
        generation = {"schema": "serverware.authorityGenerationLaunchContext/v4",
            "digest": sha(b"synthetic registration launch input, not admission"),
            "sequence": payload["generationSequence"],
            "configurationBindingDigest": payload["generationBindingDigest"],
            "predecessorDigest": payload["generationPredecessorDigest"],
            "minimumRollbackSequence": payload["generationMinimumRollbackSequence"],
            "operationManifestDigest": generator.authority_contract.OPERATION_MANIFEST_DIGEST,
            "configurationDigests": [sha(raw)],
            "configurationPayloadBindings": [{"fileDigest": sha(raw),
                "payloadDigest": framed(PAYLOAD_SCHEMA, canonical(payload)),
                "payloadSchema": PAYLOAD_SCHEMA, "role": "authority-service"}],
            "roleBindingDigests": copy.deepcopy(payload["roleBindingDigests"])}
        if generation_change is not None:
            generation_change(generation)
        originals = {"SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY": self.root.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            "SERVERWARE_POLICY_AUTHORITY_CONFIG": raw}

        def read_original(name, *, maximum, require_root_owned, require_descriptor=False):
            self.assertIs(require_root_owned, True)
            self.assertIs(require_descriptor, True)
            self.assertEqual(maximum, 64 * 1024 if name.endswith("ROOT_PUBLIC_KEY") else service.MAX_CONFIG_BYTES)
            self.descriptor_reads.append(name)
            self.assertLessEqual(len(originals[name]), maximum)
            return originals[name]

        def launch_input():
            if forbid_launch:
                self.fail("unverified configuration reached launch inputs")
            return copy.deepcopy(generation)

        def terminal(configuration):
            self.boundary_payloads.append(copy.deepcopy(configuration.payload))
            self.assertEqual(configuration.digest, framed(PAYLOAD_SCHEMA, canonical(payload)))
            self.assertEqual(configuration.original_bytes, raw)
            raise RuntimeAdmissionRefused("synthetic inputs cannot establish runtime admission")

        with patch.object(service, "_read_bounded_descriptor", side_effect=read_original), \
                patch.object(service.authority_launch_guard, "generation", side_effect=launch_input), \
                patch.object(service.authority_launch_guard, "launch_assurance",
                    return_value={"trustMode": "trusted-host-local"}), \
                patch.object(service.MeasuredConfiguration, "_verify_runtime_closure", new=terminal), \
                patch.object(service.MeasuredConfiguration, "_verify_attestation",
                    side_effect=AssertionError("attestation must remain unreachable")):
            return service.MeasuredConfiguration.load(role="planner")

    def test_full_generator_absent_policy_preserves_legacy_bytes_and_digest(self):
        original = canonical(self.payload)
        self.assertNotIn(FIELD, self.payload)
        self.assertEqual(self.generate(self.payload), (PAYLOAD_SCHEMA, framed(PAYLOAD_SCHEMA, original)))
        self.assertEqual(canonical(self.payload), original)

    def test_full_generator_accepts_exact_optional_policy_without_normalizing_other_fields(self):
        before = copy.deepcopy(self.payload)
        self.with_policy()
        original = canonical(self.payload)
        self.assertEqual(self.generate(self.payload), (PAYLOAD_SCHEMA, framed(PAYLOAD_SCHEMA, original)))
        self.assertEqual(canonical(self.payload), original)
        self.assertEqual({key: value for key, value in self.payload.items() if key != FIELD}, before)
        self.assertEqual(self.payload["roles"]["planner"]["enabledOperations"], [])

    def test_full_generator_rejects_present_null_and_closed_policy_substitutions(self):
        alternatives = [None, {}, {**self.policy, "extra": True},
            {**self.policy, "sourceContractDigest": sha(b"another source contract")},
            {**self.policy, "reservationTtlSeconds": True},
            {key: value for key, value in self.policy.items() if key != "assignmentAuthorizer"}]
        for index, policy in enumerate(alternatives):
            with self.subTest(case=index):
                payload = {**copy.deepcopy(self.original_payload), FIELD: copy.deepcopy(policy)}
                original = canonical(payload)
                with self.assertRaisesRegex(generator.GeneratorError, "native JIT review custody policy is invalid"):
                    self.generate(payload)
                self.assertEqual(canonical(payload), original)

    def test_real_signed_loader_absent_and_valid_policy_stop_at_runtime_admission(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                payload = copy.deepcopy(self.original_payload)
                if enabled:
                    payload[FIELD] = copy.deepcopy(self.policy)
                original = canonical(payload)
                with self.assertRaises(RuntimeAdmissionRefused):
                    self.load(payload)
                self.assertEqual(self.boundary_payloads[-1], payload)
                self.assertEqual(canonical(payload), original)
        self.assertEqual(len(self.boundary_payloads), 2)
        self.assertEqual(self.descriptor_reads, ["SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG"] * 2)

    def test_real_signed_loader_rejects_null_malformed_or_misnamed_policy_before_admission(self):
        for index, policy in enumerate((None, {}, {**self.policy, "extra": True},
                {**self.policy, "sourceContractDigest": sha(b"another source contract")},
                {**self.policy, "attemptCapacity": 0})):
            with self.subTest(case=index), self.assertRaisesRegex(service.AuthorityServiceError,
                    "native JIT review custody policy is invalid"):
                self.load({**copy.deepcopy(self.original_payload), FIELD: copy.deepcopy(policy)})
        with self.assertRaisesRegex(service.AuthorityServiceError, "configuration contract is invalid"):
            self.load({**self.original_payload, "nativeJitReviewCustodyPolicY": self.policy})
        self.assertEqual(self.boundary_payloads, [])

    def test_invalid_real_signature_precedes_launch_and_optional_policy_checks(self):
        for policy in (None, self.policy):
            with self.subTest(valid_policy=policy is not None), self.assertRaisesRegex(
                    service.AuthorityServiceError, "root signature is invalid"):
                self.load({**self.original_payload, FIELD: policy}, bad_signature=True, forbid_launch=True)
        self.assertEqual(self.boundary_payloads, [])

    def test_real_generation_and_topology_refuse_before_optional_policy_or_runtime(self):
        self.payload[FIELD] = None  # Invalid too, to establish failure ordering.
        with self.assertRaisesRegex(service.AuthorityServiceError, "generation binding changed"):
            self.load(self.payload, generation_change=lambda value: value.update(configurationDigests=[]))
        self.payload["roles"]["planner"]["serviceUid"] = self.payload["roles"]["verifier"]["serviceUid"]
        with self.assertRaisesRegex(service.AuthorityServiceError, "role identity or socket topology is invalid"):
            self.load(self.payload)
        self.assertEqual(self.boundary_payloads, [])

    def test_root_or_role_assignment_authorizer_alias_is_rejected_by_both_real_loaders(self):
        encoded = self.original_payload["roles"]["planner"]["signingPublicKeyBase64Url"]
        role_key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(encoded + "="))
        # Both actual original public keys, never caller-asserted SPKI claims.
        for key in (self.root.public_key(), role_key):
            pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            payload = copy.deepcopy(self.original_payload)
            payload[FIELD] = copy.deepcopy(self.policy)
            payload[FIELD]["assignmentAuthorizer"] = {"publicKeyPem": pem.decode("ascii"),
                "publicKeyPemSha256": sha(pem), "publicKeySpkiSha256": sha(der)}
            with self.subTest(key=sha(der)):
                with self.assertRaisesRegex(generator.GeneratorError, "native JIT review custody policy is invalid"):
                    self.generate(payload)
                with self.assertRaisesRegex(service.AuthorityServiceError, "native JIT review custody policy is invalid"):
                    self.load(payload)
        self.assertEqual(self.boundary_payloads, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
