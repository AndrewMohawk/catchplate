#!/usr/bin/env python3
"""Nonimporting controls for the measured writer response-public-key field.

These authored source checks do not admit configuration, load a service,
provision keys or prove a socket/ACK result. Real key behavior is exercised by
the separate configured-client component fixture when verification is allowed.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import assigned, call, calls, definition, source


FIELD = "responseSigningPublicKeyBase64Url"


class RevocationWriterPublicKeySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.service = source("serverware/authority_service.py", 2 * 1024 * 1024)
        _, cls.generator = source("scripts/authority/generate_artifact_bundle.py", 256 * 1024)
        cls.measured = definition(cls.service, "MeasuredConfiguration")
        cls.topology = definition(cls.measured, "_verify_role_topology")
        cls.document = definition(cls.generator, "_validate_configuration_document")
        branches = [node for node in ast.walk(cls.topology) if isinstance(node, ast.If)
                    and ast.unparse(node.test) == "role == 'planner-writer'"]
        cls.fields, = [node for node in branches if calls(node, "required_role_fields.update")]
        cls.writer, = [node for node in branches if calls(node, "_b64url_encode")]

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_only_writer_role_closed_sets_require_the_new_field(self):
        self.assertNotIn(FIELD, ast.literal_eval(assigned(self.topology, "common_role_fields")))
        self.shape(call(self.fields, "required_role_fields.update"), '''required_role_fields.update({
            "plannerSessionIdentityDigest", "plannerSigningSpkiDigest",
            "plannerSigningPublicKeyBase64Url", "responseSigningPublicKeyBase64Url"})''')
        closure, = [node for node in ast.walk(self.topology) if isinstance(node, ast.Compare)
                    and ast.unparse(node) == "set(role_value) != required_role_fields"]
        self.assertLess(self.fields.end_lineno, closure.lineno)
        common = assigned(self.generator, "SERVICE_ROLE_COMMON_FIELDS")
        self.assertNotIn(FIELD, ast.literal_eval(common.args[0]))
        extra = assigned(self.generator, "SERVICE_ROLE_EXTRA_FIELDS")
        for key, value in zip(extra.keys, extra.values):
            fields = ast.literal_eval(value.args[0]) if value.args else set()
            self.assertEqual(FIELD in fields, key.value == "planner-writer")
        self.shape(assigned(self.document, "expected_role_fields"),
            "SERVICE_ROLE_COMMON_FIELDS | SERVICE_ROLE_EXTRA_FIELDS[configured_role]")
        self.assertTrue(any(isinstance(node, ast.Compare)
            and ast.unparse(node) == "set(configured_role_value) != expected_role_fields"
            for node in ast.walk(self.document)))

    def test_service_requires_exact_canonical_raw32_before_real_key_and_spki_binding(self):
        self.shape(assigned(self.writer, "response_encoded"), 'role_value["responseSigningPublicKeyBase64Url"]')
        guards = [node for node in self.writer.body if isinstance(node, ast.If)]
        self.shape(guards[0].test, "type(response_encoded) is not str or len(response_encoded) != 43")
        self.shape(assigned(self.writer, "response_raw"), "_b64url_decode(response_encoded, size=32)")
        self.shape(guards[1].test, "_b64url_encode(response_raw) != response_encoded")
        self.shape(assigned(self.writer, "response_key"), "Ed25519PublicKey.from_public_bytes(response_raw)")
        self.shape(guards[2].test, '_public_spki_digest(response_key) != role_value["responseSigningSpkiDigest"]')
        for guard in guards[:3]:
            self.assertIsInstance(guard.body[0], ast.Raise)
        self.assertLess(guards[0].lineno, assigned(self.writer, "response_raw").lineno)
        self.assertLess(guards[1].lineno, assigned(self.writer, "response_key").lineno)
        self.assertLess(assigned(self.writer, "response_key").lineno, guards[2].lineno)
        digest = definition(self.service, "_public_spki_digest")
        self.shape(call(digest, "key.public_bytes"), '''key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)''')
        self.shape(call(digest, "_sha256").args[0],
            '''key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)''')

    def test_generator_uses_strict_codec_and_actual_der_hash_not_an_alias_or_key_candidate(self):
        self.shape(assigned(self.document, "response_encoded"), 'planner_writer["responseSigningPublicKeyBase64Url"]')
        guard, = [node for node in ast.walk(self.document) if isinstance(node, ast.If)
                  and ast.unparse(node.test) == "type(response_encoded) is not str or len(response_encoded) != 43"]
        self.assertIsInstance(guard.body[0], ast.Raise)
        self.shape(assigned(self.document, "response_raw"), '''strict_base64url_decode(
            response_encoded, name="planner-writer response public key", decoded_size=32)''')
        self.shape(assigned(self.document, "response_key"), "Ed25519PublicKey.from_public_bytes(response_raw)")
        self.shape(assigned(self.document, "response_der"), '''response_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)''')
        binding, = [node for node in ast.walk(self.document) if isinstance(node, ast.If)
                    and "hashlib.sha256(response_der)" in ast.unparse(node.test)]
        self.shape(binding.test, '''"sha256:" + hashlib.sha256(response_der).hexdigest()
            != planner_writer["responseSigningSpkiDigest"]''')
        self.assertIsInstance(binding.body[0], ast.Raise)
        self.assertLess(guard.lineno, assigned(self.document, "response_raw").lineno)
        self.assertLess(assigned(self.document, "response_der").lineno, binding.lineno)
        _, artifact = source("serverware/authority_artifact_spec.py", 256 * 1024)
        decoder = definition(artifact, "strict_base64url_decode")
        self.assertTrue(any(isinstance(node, ast.If) and ast.unparse(node.test) == "canonical != value"
            and isinstance(node.body[0], ast.Raise) for node in ast.walk(decoder)))

    def test_root_signed_configuration_and_source_revision_still_precede_role_admission(self):
        loader = definition(self.measured, "load")
        verified = call(loader, "root_key.verify")
        admitted = call(loader, "configuration._verify_role_topology")
        self.assertLess(verified.lineno, admitted.lineno)
        self.assertTrue(any(isinstance(node, ast.Compare)
            and ast.unparse(node) == "payload.get('sourceRevision') != SOURCE_REVISION"
            for node in ast.walk(loader)))
        self.assertTrue(any(isinstance(node, ast.Compare)
            and ast.unparse(node) == "payload['sourceRevision'] != source_revision"
            for node in ast.walk(self.document)))
        self.shape(assigned(self.service, "CONFIG_SCHEMA"), '"serverware.policyAuthorityServiceConfiguration/v5"')
        self.shape(assigned(self.generator, "SERVICE_CONFIGURATION_PAYLOAD_SCHEMA"),
            '"serverware.policyAuthorityServiceConfiguration/v5"')

    def test_other_role_and_actual_launch_key_separation_remain_required(self):
        separated, = [node for node in self.topology.body if isinstance(node, ast.If)
                      and "roles[name]['responseSigningSpkiDigest']" in ast.unparse(node.test)]
        self.shape(separated.test, '''planner_writer["responseSigningSpkiDigest"] in {
            roles[name]["responseSigningSpkiDigest"] for name in ("verifier", "planner", "issuer", "executor")}''')
        self.assertIsInstance(separated.body[0], ast.Raise)
        generated, = [node for node in ast.walk(self.document) if isinstance(node, ast.If)
                      and "for other_role in" in ast.unparse(node.test)]
        self.shape(generated.test, '''any(planner_writer["responseSigningSpkiDigest"]
            == roles[other_role]["responseSigningSpkiDigest"]
            for other_role in ("verifier", "planner", "issuer", "executor"))''')
        self.assertIsInstance(generated.body[0], ast.Raise)
        _, signer = source("serverware/authority_revocation_writer_signer.py", 64 * 1024)
        binder = definition(signer, "_signer_from_pem")
        launch, = [node for node in binder.body if isinstance(node, ast.If)
                   and ast.unparse(node.test) == "observed == _public_spki_digest(launch_public_key)"]
        self.assertIsInstance(launch.body[0], ast.Raise)
        self.shape(assigned(binder, "observed"), "_public_spki_digest(private_key.public_key())")

    def test_key_is_configuration_only_not_transfer_candidate_or_new_descriptor(self):
        text, transfer = source("serverware/authority_revocation_writer_transport.py", 64 * 1024)
        self.assertNotIn(FIELD, text)
        self.shape(assigned(transfer, "TRANSFER_SCHEMA"),
            '"serverware.policyAuthorityRevocationWriterTransfer/v1"')
        _, launcher = source("serverware/authority_launcher.py", 256 * 1024)
        inventory = assigned(launcher, "ROLE_CREDENTIAL_DESCRIPTOR_NAMES")
        writer, = [value for key, value in zip(inventory.keys, inventory.values)
                   if key.value == "planner-writer"]
        self.shape(writer, '''frozenset({
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN_FD"})''')
        for function in (self.writer, self.document):
            for forbidden in ("Ed25519PrivateKey.generate", "_load_ed25519_private_key", "socket.socket"):
                self.assertFalse(calls(function, forbidden))


if __name__ == "__main__":
    unittest.main()
