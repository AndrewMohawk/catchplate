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


class NativeJitReviewAuthorityPolicyTests(unittest.TestCase):
    """Real enrollment signatures and policy grammar, not cold service admission."""

    @classmethod
    def setUpClass(cls):
        from scripts import test_authority_native_jit_review_open as reviewer
        from scripts import test_native_jit_review_open_owner as native
        from scripts import test_oidc_activation_request_dispatch as roots
        from serverware import authority_native_jit_review_service_policy as policy
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
        cls.policy, cls.work_type, cls.limits = policy, _ValidationWork, QueryReadValidationLimits
        pki = custody_fixture.SyntheticNitro()
        opening = native.Fixture(pki, native.historical.Fixture(pki))
        current, _, _ = roots.head_fixture()
        cls.root = current["root_public_key"]
        cls.enrollment = current["enrollment_bytes"]
        cls.generation = json.loads(cls.enrollment)["payload"]["generationDigest"]
        selected = reviewer.ReviewerFixture()
        cls.original = copy.deepcopy(opening.configuration)
        cls.original["webauthn"] = dict(rpId="portal.synthetic.invalid",
            origin=opening.policy["portalOrigin"], challengeLifetimeNs=30_000_000_000,
            maximumChallengeAgeNs=30_000_000_000, allowedAuthenticatorClasses=["hardware"],
            requireAttestationTrusted=True)
        cls.original[policy.FIELD] = dict(schema=policy.SCHEMA,
            sourceContractDigest=policy.authority.OPERATION_MANIFEST_DIGEST,
            authenticationPolicy=selected.authn, trustPolicy=selected.trust,
            stateEndpoint=dict(socketPath="/run/serverware/current-root/state.sock",
                requestTimeoutSeconds=5, listenerUid=0, listenerGid=0))

    def setUp(self):
        self.payload = copy.deepcopy(self.original)

    def tearDown(self):
        self.assertEqual(_external_violations, [])

    def work(self, **limits):
        return self.work_type(self.limits(**limits))

    def admit(self, **changes):
        arguments = dict(configuration_payload=self.payload, configuration_root_key=self.root,
            enrollment_original=self.enrollment, expected_generation_digest=self.generation, work=self.work())
        arguments.update(changes)
        return self.policy.admit_on_work(self.payload[self.policy.FIELD], **arguments)

    def refused(self, action):
        with self.assertRaisesRegex(self.policy.NativeJitReviewServicePolicyError,
                "^" + self.policy.ERROR + "$") as caught:
            action()
        self.assertIsNone(caught.exception.__cause__)

    def test_real_root_enrollment_exact_generation_and_immutable_owned_material(self):
        before = copy.deepcopy(self.payload)
        actual = self.admit()
        self.assertEqual(actual.authentication_policy, before[self.policy.FIELD]["authenticationPolicy"])
        self.assertEqual(actual.trust_policy, before[self.policy.FIELD]["trustPolicy"])
        self.assertIs(actual.enrollment_original, self.enrollment)
        self.assertEqual(actual.state_configuration, ("/run/serverware/current-root/state.sock", 5, 0, 0))
        self.assertEqual(self.payload, before)
        actual.authentication_policy["allowedAuthenticatorClasses"].clear()
        actual.trust_policy["roots"][0]["aaguids"].clear()
        self.assertEqual(actual.authentication_policy, before[self.policy.FIELD]["authenticationPolicy"])
        self.assertEqual(actual.trust_policy, before[self.policy.FIELD]["trustPolicy"])
        with self.assertRaises(AttributeError):
            actual.enrollment_original = b"{}"
        validated = self.policy.validate_policy(self.payload[self.policy.FIELD], payload=self.payload, root_key=self.root)
        self.assertEqual(validated, before[self.policy.FIELD])
        self.assertIsNot(validated, self.payload[self.policy.FIELD])

    def test_absent_is_optional_but_null_extra_embedded_enrollment_and_other_source_refuse(self):
        del self.payload[self.policy.FIELD]
        self.assertIsNone(self.policy.validate_policy(None, payload=self.payload, root_key=self.root))
        for replacement in (None, {}, dict(self.original[self.policy.FIELD], verified=True),
                dict(self.original[self.policy.FIELD], currentRootEnrollment={"base64Url": "e30", "byteCount": 2}),
                dict(self.original[self.policy.FIELD], sourceContractDigest="sha256:" + "f" * 64)):
            with self.subTest(value_type=type(replacement).__name__):
                self.payload[self.policy.FIELD] = replacement
                self.refused(lambda: self.policy.validate_policy(replacement, payload=self.payload, root_key=self.root))
        self.payload = copy.deepcopy(self.original)
        other = copy.deepcopy(self.payload[self.policy.FIELD]); other["stateEndpoint"]["requestTimeoutSeconds"] = 6
        self.refused(lambda: self.policy.validate_policy(other, payload=self.payload, root_key=self.root))

    def test_existing_opening_policy_and_exact_configured_audience_remain_required(self):
        for change in ("missing", "null", "portal", "classes", "attestation", "verification", "bundle"):
            with self.subTest(change=change):
                self.payload = copy.deepcopy(self.original)
                policy = self.payload[self.policy.FIELD]
                if change == "missing": del self.payload[self.policy.opening.FIELD]
                elif change == "null": self.payload[self.policy.opening.FIELD] = None
                elif change == "portal": self.payload["webauthn"]["origin"] = "https://other.synthetic.invalid"
                elif change == "classes": policy["authenticationPolicy"]["allowedAuthenticatorClasses"] = ["platform"]
                elif change == "attestation": policy["authenticationPolicy"]["requireHardwareAttestation"] = False
                elif change == "verification": policy["authenticationPolicy"]["userVerification"] = "preferred"
                else: policy["trustPolicy"]["roots"][0]["bundle_sequence"] += 1
                self.refused(self.admit)

    def test_state_endpoint_is_fixed_root_peer_and_bounded_integer_timeout(self):
        for field, value in (("socketPath", "/tmp/state.sock"), ("listenerUid", 1),
                ("listenerGid", 1), ("listenerUid", False), ("requestTimeoutSeconds", 0),
                ("requestTimeoutSeconds", 31), ("requestTimeoutSeconds", 0.5), ("verified", True)):
            with self.subTest(field=field, value=value):
                self.payload = copy.deepcopy(self.original)
                self.payload[self.policy.FIELD]["stateEndpoint"][field] = value
                self.refused(self.admit)

    def test_enrollment_signature_source_original_bytes_and_launch_generation_are_exact(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        changed = json.loads(self.enrollment)
        signature = changed["signatureBase64Url"]
        changed["signatureBase64Url"] = ("A" if signature[0] != "A" else "B") + signature[1:]
        bad_source = json.loads(self.enrollment)
        bad_source["payload"]["sourceRevision"] += ".future"
        for raw in (b"{}", bytearray(self.enrollment), self.enrollment + b"\n",
                canonical(changed), canonical(bad_source)):
            with self.subTest(original_type=type(raw).__name__):
                self.refused(lambda: self.admit(enrollment_original=raw))
        for generation in (None, "sha256:" + "f" * 64):
            self.refused(lambda: self.admit(expected_generation_digest=generation))
        self.refused(lambda: self.admit(configuration_root_key=
            Ed25519PrivateKey.from_private_bytes(b"\x69" * 32).public_key()))

    def test_shared_work_exhaustion_and_finite_configuration_capture(self):
        self.payload["roles"]["planner"]["requestTimeoutSeconds"] = 0.5
        self.admit()
        for budget in (dict(max_input_bytes=64), dict(max_hashes=1), dict(max_json_nodes=2)):
            with self.subTest(budget=budget):
                meter = self.work(**budget)
                self.refused(lambda: self.admit(work=meter))
                self.assertGreater(meter.input_bytes + meter.json_nodes, 0)
        self.payload["roles"]["planner"]["requestTimeoutSeconds"] = float("inf")
        self.refused(self.admit)

    def test_caller_mutation_during_crypto_cannot_rewrite_held_policy(self):
        actual_validator = self.policy.opening.validate_policy
        def mutate_then_validate(*args, **kwargs):
            self.payload["webauthn"]["origin"] = "https://changed.synthetic.invalid"
            self.payload[self.policy.FIELD]["authenticationPolicy"]["allowedAuthenticatorClasses"].clear()
            return actual_validator(*args, **kwargs)
        with patch.object(self.policy.opening, "validate_policy", side_effect=mutate_then_validate):
            admitted = self.admit()
        self.assertEqual(admitted.authentication_policy, self.original[self.policy.FIELD]["authenticationPolicy"])


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

    def test_full_generator_and_signed_loader_join_authority_and_opening_policies_before_runtime_refusal(self):
        from scripts import test_authority_native_jit_review_open as reviewer
        from scripts import test_native_jit_review_open_owner as native
        from serverware import authority_native_jit_review_service_policy as authority_policy
        pki = custody_fixture.SyntheticNitro()
        opening = native.Fixture(pki, native.historical.Fixture(pki))
        audience = self.payload["webauthn"]
        audience["allowedAuthenticatorClasses"] = ["hardware"]
        self.payload[authority_policy.opening.FIELD] = copy.deepcopy(opening.policy)
        self.payload[authority_policy.opening.FIELD]["portalOrigin"] = audience["origin"]
        selected = reviewer.ReviewerFixture()
        self.payload[authority_policy.FIELD] = dict(schema=authority_policy.SCHEMA,
            sourceContractDigest=authority_policy.authority.OPERATION_MANIFEST_DIGEST,
            authenticationPolicy=selected.authn, trustPolicy=selected.trust,
            stateEndpoint=dict(socketPath="/run/serverware/current-root/state.sock",
                requestTimeoutSeconds=5, listenerUid=0, listenerGid=0))
        original = canonical(self.payload)
        self.assertEqual(self.generate(self.payload),
            (PAYLOAD_SCHEMA, framed(PAYLOAD_SCHEMA, original)))
        with self.assertRaisesRegex(RuntimeAdmissionRefused,
                "synthetic inputs cannot establish runtime admission"):
            self.load(self.payload)
        self.assertEqual(self.boundary_payloads, [self.payload])
        self.assertEqual(canonical(self.payload), original)
        self.assertNotIn("currentRootEnrollment", self.payload[authority_policy.FIELD])
        self.assertEqual(self.descriptor_reads, ["SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG"])

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


class NativeJitReviewServiceBoundaryTests(unittest.TestCase):
    """Disabled/invalid startup only; these do not fake a cold admitted owner."""

    def test_unstarted_owner_is_refused_before_receiving_a_session_token(self):
        from serverware import authority_native_jit_review_service as opening
        with patch.object(opening.transport, "recv_request") as receive:
            with self.assertRaises(opening.NativeReviewServiceError):
                opening.serve_process(object(), None, deadline_ns=1,
                    prefix=opening.transport.REQUEST_MAGIC)
            receive.assert_not_called()

    def test_absent_policy_does_not_load_an_enrollment_or_signer(self):
        from serverware import authority_native_jit_review_service as opening
        process = object.__new__(service.AuthorityProcess)
        process.role_name = "planner"
        process.configuration = service.MeasuredConfiguration(payload={}, digest="", root_key=None)
        try:
            with patch.dict(os.environ, {}, clear=True), \
                    patch.object(opening.sealed, "_read_original") as read, \
                    patch.object(opening.signers, "_borrow") as borrow:
                opening.initialize(process)
                self.assertIsNone(opening._OWNERS[process])
                read.assert_not_called()
                borrow.assert_not_called()
        finally:
            opening._OWNERS.pop(process, None)

    def test_absent_policy_rejects_ambient_enrollment_instead_of_selecting_it(self):
        from serverware import authority_native_jit_review_service as opening
        process = object.__new__(service.AuthorityProcess)
        process.role_name = "planner"
        process.configuration = service.MeasuredConfiguration(payload={}, digest="", root_key=None)
        for name in (opening.ENVIRONMENT, opening.ENVIRONMENT.removesuffix("_FD") + "_PATH"):
            with self.subTest(name=name), patch.dict(os.environ, {name: "123"}, clear=True), \
                    patch.object(opening.sealed, "_read_original") as read:
                with self.assertRaises(opening.NativeReviewServiceError):
                    opening.initialize(process)
                self.assertNotIn(process, opening._OWNERS)
                read.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
