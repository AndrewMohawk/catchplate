#!/usr/bin/env python3
"""Synthetic cryptographic JIT custody controls, not native admission.

All keys, certificates, COSE documents, clocks and encrypted review documents
are local synthetic fixtures. Actual signature, certificate and byte-binding
validators run; no native owner or successful attestation verdict is mocked.
No hardware, startup, database, provider, review disclosure or deployment is
performed or established by this suite.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
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
        raise AssertionError("synthetic JIT custody controls forbid external effects")


if __name__ == "__main__":
    os.environ["SERVERWARE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
    sys.addaudithook(no_external_effects)

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
from scripts import test_authority_release_private_request as release_fixture
from scripts import test_native_jit_prepare as preparation_fixture
from serverware import authority_contract as contract
from serverware import authority_native_jit_review_assignment as assignment
from serverware import authority_native_jit_review_custody as custody
from serverware import authority_release_private_request as private
from serverware import native_jit_review_material as material

SECOND = 1_000_000_000
NOW = 1_800_000_000 * SECOND
MONO = 500 * SECOND
FIELD = "nativeJitReviewCustodyPolicy"
ASSIGNMENT_SCHEMA = "serverware.nativeJitReviewAssignment/v1"
SIGNED_ASSIGNMENT_SCHEMA = "serverware.signedNativeJitReviewAssignment/v1"
STATEMENT_SCHEMA = "serverware.nativeReleaseJitReviewStatement/v1"
SIGNATURE_DOMAIN = STATEMENT_SCHEMA.encode("ascii") + b"\0"
ATTESTATION_DOMAIN = b"serverware/native-release-jit-review-attestation/v1\0"
IDENTITY_FIELDS = ("holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId",
    "releaseRecordSha256", "policyHash", "configurationSha256", "caCertificateSha256",
    "caPublicKeySpkiSha256", "expectedBinaryDigest")
QUOTE_SCOPE_FIELDS = ("releaseRecordSha256", "policyHash", "configurationSha256",
    "caCertificateSha256", "caPublicKeySpkiSha256")
KEY = bytes(range(32))  # Public fixture material, never provisioned.
KEY_ID = "attested-memory-kek:" + hashlib.sha256(KEY).hexdigest()[:24]


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("ascii")


def sha256(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def framed(domain, raw):
    return sha256(domain.encode("ascii") + b"\0" + len(raw).to_bytes(8, "big") + raw)


def encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def public_spki(key):
    return key.public_key().public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def key_descriptor(key):
    pem = public_pem(key)
    return {"publicKeyPem": pem.decode("ascii"), "publicKeyPemSha256": sha256(pem),
        "publicKeySpkiSha256": sha256(public_spki(key))}


class SyntheticNitro:
    """Real local P-384 signatures; deliberately not an AWS trust claim."""

    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.leaf_key = ec.generate_private_key(ec.SECP384R1())
        self.root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
            "synthetic JIT custody test root")])
        self.root = self.certificate(self.root_name, self.root_key.public_key(), ca=True, serial=1)
        self.leaf = self.certificate(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
            "synthetic JIT custody test leaf")]), self.leaf_key.public_key(), ca=False, serial=2)

    def certificate(self, subject, public, *, ca, serial):
        at = datetime.fromtimestamp(NOW // SECOND, timezone.utc)
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(self.root_name)
            .public_key(public).serial_number(serial).not_valid_before(at - timedelta(hours=1))
            .not_valid_after(at + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True)
            .sign(self.root_key, hashes.SHA384()))

    def quote(self, *, public_key, user_data, nonce, pcrs, module_id="synthetic-jit-module", now=NOW):
        protected = cbor2.dumps({1: -35}, canonical=True)
        payload = cbor2.dumps({"module_id": module_id, "timestamp": now // 1_000_000,
            "digest": "SHA384", "pcrs": {int(name[3:]): bytes.fromhex(value[7:])
                for name, value in pcrs.items()},
            "certificate": self.leaf.public_bytes(serialization.Encoding.DER),
            "cabundle": [self.root.public_bytes(serialization.Encoding.DER)],
            "public_key": public_key, "user_data": user_data, "nonce": nonce}, canonical=True)
        der = self.leaf_key.sign(cbor2.dumps(["Signature1", protected, b"", payload]),
            ec.ECDSA(hashes.SHA384()))
        r, s = utils.decode_dss_signature(der)
        return cbor2.dumps([protected, {}, payload, r.to_bytes(48, "big") + s.to_bytes(48, "big")], canonical=True)


class Fixture:
    """Explicit synthetic originals, not a native Owner or admitted startup."""

    def __init__(self, pki, *, capacity=4, owner_capacity=None, reservation_ttl=None):
        self.pki = pki
        self.root, self.authorizer, self.native, self.response, self.role = [
            ed25519.Ed25519PrivateKey.from_private_bytes(bytes([number]) * 32)
            for number in (11, 12, 13, 14, 15)]
        raw = preparation_fixture.raw_parent(preparation_fixture.payload())
        self.runtime = private.prepare(raw)
        assert canonical(self.runtime) == canonical(release_fixture.expected_envelope(raw))
        self.parent = release_fixture.native_request_oracle("release.reserve", self.runtime["arguments"])
        self.child = release_fixture.native_request_oracle("jit.request", self.runtime["arguments"]["jit_approval_request"])
        assert self.parent["operationManifestDigest"] == contract.OPERATION_MANIFEST_DIGEST
        boot = b"b" * 32
        key_id = sha256(public_spki(self.native))
        self.target = {"controlPlaneResponseSigningKeyId": sha256(public_spki(self.response)),
            "releaseRecordSha256": sha256(b"synthetic release original"), "policyHash": raw["policy_hash"],
            "expectedBinaryDigest": sha256(b"synthetic non-executable binary identity"),
            "expectedPcrs": {"PCR" + str(index): "sha384:" + str(index + 1) * 96 for index in range(3)},
            "expectedEif": "sha384:" + "1" * 96, "maxAgeSeconds": 30, "futureSkewSeconds": 0,
            "instanceId": raw["actor_id"], "secretKekId": KEY_ID}
        self.selected = {**self.target, "bootId": encoded(boot), "keyId": key_id,
            "holderId": sha256(b"serverware/credential-currentness-holder/v1\0" + boot + bytes.fromhex(key_id[7:])),
            "configurationSha256": sha256(b"synthetic complete native configuration original"),
            "caCertificateSha256": sha256(pki.root.public_bytes(serialization.Encoding.DER)),
            "caPublicKeySpkiSha256": sha256(pki.root_key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
            "expectedModuleId": "synthetic-jit-module"}
        self.policy = {"schema": "serverware.nativeJitReviewCustodyAuthorityPolicy/v1",
            "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "reservationTtlSeconds": raw["reservation_ttl_seconds"] if reservation_ttl is None else reservation_ttl,
            "operationMaxSeconds": 30,
            "attemptCapacity": capacity, "deploymentId": "synthetic-jit-custody",
            "assignmentAuthorizer": key_descriptor(self.authorizer), "target": copy.deepcopy(self.target),
            "trustRoots": {"apiVersion": "serverware.nativeJitReviewNativeTrustRoots/v1",
                "awsNitroRootCertificatesPem": [pki.root.public_bytes(serialization.Encoding.PEM).decode("ascii")],
                "awsNitroCrlsDerBase64url": [], "nitroCertificateProfile": {
                    "profileId": "aws-nitro-attestation-pki-native-v1", "allowedLeafExtendedKeyUsageOids": []}}}
        self.configuration = {"schema": "serverware.policyAuthorityServiceConfiguration/v6",
            "sourceRevision": contract.SOURCE_REVISION, "roles": {"planner": {
                "enabledOperations": ["jit.request", "release.reserve"],
                "signingKeySpkiDigest": sha256(public_spki(self.role))}}, FIELD: self.policy}
        self.configuration_digest = framed("serverware.policyAuthorityServiceConfiguration/v6", canonical(self.configuration))
        self.assignment_payload = {"schema": ASSIGNMENT_SCHEMA,
            "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": self.configuration_digest,
            "deploymentId": self.policy["deploymentId"], "assignment": copy.deepcopy(self.selected),
            "issuedAtEpochNs": NOW - SECOND, "expiresAtEpochNs": NOW + 600 * SECOND}
        self.assignment_original = self.sign_assignment()
        # Independent literal owner configuration: do not call the verifier's
        # reconstruction helper to produce its own expected commitment.
        broker = {"apiVersion": "serverware.nativeJitReviewConfiguration/v1",
            "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": self.configuration_digest,
            "deploymentId": self.policy["deploymentId"], "instanceId": raw["actor_id"],
            "secretKekId": KEY_ID, "attemptCapacity": capacity if owner_capacity is None else owner_capacity,
            "identity": {name: self.selected[name] for name in IDENTITY_FIELDS}}
        self.scope = {"schema": "serverware.nativeJitReviewScope/v2", "publicRequest": self.child,
            "parentRequestSha256": sha256(canonical(self.parent)),
            "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": self.configuration_digest,
            "ownerScopeDigest": sha256(canonical(broker)), "issuedAtEpochNs": NOW,
            "sealExpiresAtEpochNs": NOW + 30 * SECOND, "documentExpiresAtEpochNs": NOW + 300 * SECOND}
        self.pair = material.seal_release_pair(self.scope, self.runtime["privateDocuments"],
            key_id=KEY_ID, kek=AESGCM(KEY), now_epoch_ns=NOW)
        self.statement = {"apiVersion": STATEMENT_SCHEMA, "operation": "nativeReleaseJitReview.sign/v1",
            **{name: self.selected[name] for name in IDENTITY_FIELDS},
            "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": self.configuration_digest,
            "ownerScopeDigest": self.scope["ownerScopeDigest"], "deploymentId": self.policy["deploymentId"],
            "instanceId": raw["actor_id"], "secretKekId": KEY_ID,
            "requestDigest": self.child["requestDigest"], "operationId": self.child["operationId"],
            "publicRequestSha256": sha256(canonical(self.child)), "pairSha256": sha256(canonical(self.pair)),
            "parentRequestSha256": sha256(canonical(self.parent)),
            "parentRequestDigest": self.parent["requestDigest"], "parentOperationId": self.parent["operationId"],
            "challenge": encoded(b"c" * 32), "issuedAtEpochNs": NOW,
            "expiresAtEpochNs": NOW + 30 * SECOND, "documentExpiresAtEpochNs": NOW + 300 * SECOND}
        self.proof = self.sign_proof()

    def sign_assignment(self, *, domain=SIGNED_ASSIGNMENT_SCHEMA, key=None):
        signature = (key or self.authorizer).sign(framed(domain, canonical(self.assignment_payload)).encode("ascii"))
        return canonical({"schema": SIGNED_ASSIGNMENT_SCHEMA, "payload": self.assignment_payload,
            "signature": encoded(signature)}).decode("ascii")

    def sign_proof(self, *, domain=SIGNATURE_DOMAIN, nonce_domain=ATTESTATION_DOMAIN,
            quote_changes=None, native_key=None):
        signer = native_key or self.native
        statement_raw = canonical(self.statement)
        signature = signer.sign(domain + statement_raw)
        raw_key = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        boot_binding = hashlib.sha256(b"serverware/native-proof-custody-boot/v1\0" + b"b" * 32
            + bytes.fromhex(self.selected["keyId"][7:])
            + bytes.fromhex(self.selected["controlPlaneResponseSigningKeyId"][7:])).digest()
        user_data = b"serverware/enclave-runtime-key-binding/v1\0\x04" + b"".join(
            bytes.fromhex(self.selected[name][7:]) for name in QUOTE_SCOPE_FIELDS)
        user_data += hashlib.sha256(raw_key).digest() + boot_binding
        arguments = {"public_key": raw_key, "user_data": user_data,
            "nonce": hashlib.sha256(nonce_domain + b"c" * 32 + hashlib.sha256(statement_raw).digest() + signature).digest(),
            "pcrs": self.target["expectedPcrs"]}
        arguments.update(quote_changes or {})
        quote = self.pki.quote(**arguments)
        return {"statement": copy.deepcopy(self.statement), "signature": "ed25519:" + encoded(signature),
            "assignmentOriginal": self.assignment_original, "nativeKeyEvidence": {
                "apiVersion": "serverware.nativeResponseProofKeyEvidence/v1", "responseProofPublicKey": encoded(raw_key),
                "attestationDocumentB64": encoded(quote)}}

    def arguments(self):
        return {"runtime_original": canonical(self.runtime).decode("ascii"),
            "parent_original": canonical(self.parent).decode("ascii"), "child_original": canonical(self.child).decode("ascii"),
            "pair_original": canonical(self.pair).decode("ascii"), "evidence_original": canonical(self.proof).decode("ascii"),
            "configuration_payload": self.configuration, "root_key": self.root.public_key(),
            "now_epoch_ns": NOW, "deadline_monotonic_ns": MONO + 29 * SECOND}


class NativeJitCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = SyntheticNitro()

    def setUp(self):
        self.fixture = Fixture(self.pki)

    def tearDown(self):
        self.assertEqual(_external_violations, [], "external I/O refusal cannot be counted as a passing negative")

    def verify(self, *, wall=NOW, monotonic=MONO, **changes):
        with patch.object(custody.time, "time_ns", return_value=wall), \
                patch.object(custody.time, "monotonic_ns", return_value=monotonic):
            return custody.verify_original(**(self.fixture.arguments() | changes))

    def refused(self, call):
        with self.assertRaisesRegex(assignment.AdmissionError,
                "^native JIT review custody is unavailable$") as caught:
            call()
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn("synthetic-private-query", str(caught.exception))

    def test_real_synthetic_crypto_and_exact_encrypted_pair_are_accepted_without_verdict_carrier(self):
        f = self.fixture
        self.assertEqual(set(f.selected), assignment.ASSIGNMENT_FIELDS)
        self.assertEqual(set(f.statement), custody.STATEMENT_FIELDS)
        self.assertEqual(material.open_release_pair(f.pair, expected_scope=f.scope, key_id=KEY_ID,
            kek=AESGCM(KEY), now_epoch_ns=NOW), f.runtime["privateDocuments"])
        self.assertIsNone(self.verify())

    def test_exact_assignment_signature_returns_selection_not_native_authority(self):
        f = self.fixture
        selected = assignment.verify_original(f.assignment_original, configuration_payload=f.configuration,
            root_key=f.root.public_key(), now_epoch_ns=NOW)
        self.assertEqual(selected, f.assignment_payload)
        self.assertNotIn("okForAction", selected)
        self.assertNotIn("verified", selected)

    def test_absent_jit_policy_does_not_enable_or_borrow_another_purpose(self):
        f = self.fixture
        changed = copy.deepcopy(f.configuration); del changed[FIELD]
        self.assertIsNone(custody.validate_policy(None, payload=changed, root_key=f.root.public_key()))
        self.refused(lambda: self.verify(configuration_payload=changed))
        changed[FIELD] = None
        self.refused(lambda: custody.validate_policy(None, payload=changed, root_key=f.root.public_key()))

    def test_closed_policy_and_exact_current_source_are_required(self):
        f = self.fixture
        for field, value in (("extra", True), ("schema", "serverware.staticCredentialCustodyAuthorityPolicy/v2"),
                ("sourceContractDigest", sha256(b"different source"))):
            changed = copy.deepcopy(f.policy); changed[field] = value
            with self.subTest(field=field):
                self.refused(lambda: custody.validate_policy(changed, payload=f.configuration, root_key=f.root.public_key()))

    def test_policy_ttl_capacity_and_integer_bounds_are_closed(self):
        f = self.fixture
        for field, limit in (("reservationTtlSeconds", 300), ("operationMaxSeconds", 30), ("attemptCapacity", 16)):
            for value in (0, limit + 1, True, "1", 1.5):
                changed = copy.deepcopy(f.policy); changed[field] = value
                with self.subTest(field=field, value=value):
                    self.refused(lambda: custody.validate_policy(changed, payload=f.configuration, root_key=f.root.public_key()))
        for capacity in (1, 16):
            self.fixture = Fixture(self.pki, capacity=capacity)
            self.assertIsNone(self.verify())

    def test_assignment_authorizer_cannot_alias_root_role_or_response_keys(self):
        f = self.fixture
        for key in (f.root, f.role, f.response):
            changed = copy.deepcopy(f.policy); changed["assignmentAuthorizer"] = key_descriptor(key)
            self.refused(lambda: custody.validate_policy(changed, payload=f.configuration, root_key=f.root.public_key()))

    def test_assignment_signature_and_purpose_domain_are_not_interchangeable(self):
        f = self.fixture
        for original in (f.sign_assignment(domain="serverware.signedStaticCredentialAssignment/v1"),
                f.sign_assignment(key=f.native)):
            self.refused(lambda: assignment.verify_original(original, configuration_payload=f.configuration,
                root_key=f.root.public_key(), now_epoch_ns=NOW))

    def test_assignment_literal_parser_is_closed_canonical_and_not_signature_admission(self):
        f = self.fixture
        envelope = json.loads(f.assignment_original); envelope["signature"] = encoded(bytes(64))
        invalid_signature = canonical(envelope).decode("ascii")
        self.assertEqual(assignment.original(invalid_signature)["payload"], f.assignment_payload)
        self.refused(lambda: assignment.verify_original(invalid_signature, configuration_payload=f.configuration,
            root_key=f.root.public_key(), now_epoch_ns=NOW))
        for original in (f.assignment_original + "\n", f.assignment_original.replace('{', '{"schema":"duplicate",', 1),
                canonical({**envelope, "verified": True}).decode("ascii")):
            self.refused(lambda: assignment.original(original))

    def test_assignment_original_interval_and_maximum_lifetime_are_enforced(self):
        f = self.fixture
        for at in (f.assignment_payload["issuedAtEpochNs"] - 1, f.assignment_payload["expiresAtEpochNs"]):
            self.refused(lambda: assignment.verify_original(f.assignment_original, configuration_payload=f.configuration,
                root_key=f.root.public_key(), now_epoch_ns=at))
        f.assignment_payload["expiresAtEpochNs"] = f.assignment_payload["issuedAtEpochNs"] + 86_400 * SECOND + 1
        self.refused(lambda: assignment.original(f.sign_assignment()))

    def test_assignment_binds_full_configuration_source_deployment_and_fixed_target(self):
        f = self.fixture
        for field, value in (("controlPlaneConfigurationDigest", sha256(b"other configuration")),
                ("sourceContractDigest", sha256(b"other source")), ("deploymentId", "other-deployment")):
            changed = copy.deepcopy(f.assignment_payload); changed[field] = value
            before = f.assignment_payload; f.assignment_payload = changed
            original = f.sign_assignment(); f.assignment_payload = before
            self.refused(lambda: assignment.verify_original(original, configuration_payload=f.configuration,
                root_key=f.root.public_key(), now_epoch_ns=NOW))
        f.assignment_payload["assignment"]["expectedBinaryDigest"] = sha256(b"other binary")
        self.refused(lambda: assignment.verify_original(f.sign_assignment(), configuration_payload=f.configuration,
            root_key=f.root.public_key(), now_epoch_ns=NOW))

    def test_native_signer_cannot_supply_its_own_assignment_or_other_authority_purpose(self):
        f = self.fixture
        for key in (f.root, f.role, f.response, f.authorizer):
            changed = copy.deepcopy(f.assignment_payload)
            key_id = sha256(public_spki(key)); changed["assignment"]["keyId"] = key_id
            changed["assignment"]["holderId"] = sha256(b"serverware/credential-currentness-holder/v1\0"
                + b"b" * 32 + bytes.fromhex(key_id[7:]))
            before = f.assignment_payload; f.assignment_payload = changed
            original = f.sign_assignment(); f.assignment_payload = before
            self.refused(lambda: assignment.verify_original(original, configuration_payload=f.configuration,
                root_key=f.root.public_key(), now_epoch_ns=NOW))

    def test_closed_evidence_parser_does_not_authenticate_signature_or_quote(self):
        f = self.fixture
        proof = copy.deepcopy(f.proof); proof["signature"] = "ed25519:" + encoded(bytes(64))
        original = canonical(proof).decode("ascii")
        self.assertEqual(custody.authority_evidence(original)["statement"], f.statement)
        self.refused(lambda: self.verify(evidence_original=original))
        for change in ({**f.proof, "okForAction": True}, {**f.proof, "assignmentOriginal": "{}"}):
            self.refused(lambda: custody.authority_evidence(canonical(change).decode("ascii")))

    def test_statement_signature_and_attestation_nonce_have_separate_exact_domains(self):
        f = self.fixture
        for proof in (f.sign_proof(domain=b"serverware.nativeJitReviewStatement/v1\0"),
                f.sign_proof(nonce_domain=b"serverware/native-jit-review-attestation/v1\0"),
                f.sign_proof(native_key=f.response)):
            self.refused(lambda: self.verify(evidence_original=canonical(proof).decode("ascii")))

    def test_real_quote_certificate_signature_module_pcr_key_and_scope_are_checked(self):
        f = self.fixture
        changes = [{"nonce": b"n" * 32}, {"module_id": "different-module"},
            {"pcrs": {**f.target["expectedPcrs"], "PCR1": "sha384:" + "9" * 96}},
            {"public_key": b"x" * 32}, {"user_data": b"not-the-bound-role-four-scope"},
            {"now": NOW - 31 * SECOND}]
        for change in changes:
            proof = f.sign_proof(quote_changes=change)
            self.refused(lambda: self.verify(evidence_original=canonical(proof).decode("ascii")))
        proof = copy.deepcopy(f.proof)
        quote = bytearray(base64.urlsafe_b64decode(proof["nativeKeyEvidence"]["attestationDocumentB64"] + "=="))
        quote[-1] ^= 1; proof["nativeKeyEvidence"]["attestationDocumentB64"] = encoded(quote)
        self.refused(lambda: self.verify(evidence_original=canonical(proof).decode("ascii")))

    def test_private_runtime_parent_child_and_pair_originals_cannot_be_substituted(self):
        f = self.fixture
        for name in ("runtime_original", "parent_original", "child_original", "pair_original"):
            value = json.loads(f.arguments()[name]); value["extra"] = "not admitted"
            self.refused(lambda: self.verify(**{name: canonical(value).decode("ascii")}))
        changed = copy.deepcopy(f.parent); changed["requestDigest"] = sha256(b"other parent")
        self.refused(lambda: self.verify(parent_original=canonical(changed).decode("ascii")))
        changed = copy.deepcopy(f.child); changed["operationId"] = sha256(b"other child")
        self.refused(lambda: self.verify(child_original=canonical(changed).decode("ascii")))

    def test_standalone_pair_cannot_replace_compound_pair(self):
        f = self.fixture
        scope = {key: value for key, value in f.scope.items() if key != "parentRequestSha256"}
        scope["schema"] = "serverware.nativeJitReviewScope/v1"
        pair = material.seal_pair(scope, f.runtime["privateDocuments"], key_id=KEY_ID, kek=AESGCM(KEY), now_epoch_ns=NOW)
        self.refused(lambda: self.verify(pair_original=canonical(pair).decode("ascii")))

    def test_pair_order_plaintext_commitments_and_lengths_match_both_private_documents(self):
        f = self.fixture
        variants = []
        pair = copy.deepcopy(f.pair); pair["items"].reverse(); variants.append(pair)
        for field, value in (("plaintextBytes", 1), ("plaintextSha256", sha256(b"other plaintext")),
                ("opaqueId", "11111111-1111-4111-8111-111111111111"), ("valueKind", "approval-secret-json/v1")):
            pair = copy.deepcopy(f.pair); pair["items"][1][field] = value; variants.append(pair)
        for pair in variants:
            self.refused(lambda: self.verify(pair_original=canonical(pair).decode("ascii")))

    def test_signed_statement_binding_changes_fail_even_with_fresh_valid_signature_and_quote(self):
        f = self.fixture
        original = copy.deepcopy(f.statement)
        for field in ("sourceContractDigest", "controlPlaneConfigurationDigest", "ownerScopeDigest", "parentRequestSha256",
                "parentRequestDigest", "parentOperationId", "publicRequestSha256", "requestDigest", "operationId", "pairSha256"):
            f.statement = {**original, field: sha256(b"changed binding")}
            proof = f.sign_proof()
            self.refused(lambda: self.verify(evidence_original=canonical(proof).decode("ascii")))
        f.statement = original

    def test_configured_capacity_is_part_of_the_exact_owner_scope(self):
        f = self.fixture
        configuration = copy.deepcopy(f.configuration); configuration[FIELD]["attemptCapacity"] += 1
        self.refused(lambda: self.verify(configuration_payload=configuration))
        # Re-signed statement alone cannot replace the independently selected
        # original owner/configuration or enlarge its configured attempt budget.
        f.statement["ownerScopeDigest"] = sha256(b"same identity but larger capacity")
        self.refused(lambda: self.verify(evidence_original=canonical(f.sign_proof()).decode("ascii")))
        self.fixture = Fixture(self.pki, capacity=4, owner_capacity=5)
        self.refused(lambda: self.verify())

    def test_wall_clock_and_original_monotonic_deadline_are_not_renewable(self):
        for changes in ({"now_epoch_ns": NOW + 1}, {"now_epoch_ns": NOW - 1},
                {"wall": NOW + 30 * SECOND}, {"deadline_monotonic_ns": MONO}):
            self.refused(lambda: self.verify(**changes))
        # A longer caller budget is locally narrowed to the original signed
        # seal window; it does not require the caller to predict that window.
        self.assertIsNone(self.verify(deadline_monotonic_ns=MONO + 60 * SECOND))

    def test_expiry_and_clock_regression_after_crypto_refuse_success(self):
        for walls, clocks in (([NOW, NOW + 30 * SECOND], [MONO, MONO + SECOND]),
                ([NOW, NOW - 1], [MONO, MONO + SECOND]),
                ([NOW, NOW], [MONO, MONO + 29 * SECOND]),
                ([NOW, NOW], [MONO, MONO - 1])):
            with patch.object(custody.time, "time_ns", side_effect=walls), \
                    patch.object(custody.time, "monotonic_ns", side_effect=clocks):
                self.refused(lambda: custody.verify_original(**self.fixture.arguments()))
        with patch.object(custody.time, "time_ns", return_value=NOW), \
                patch.object(custody.time, "monotonic_ns", side_effect=[MONO, MONO + 30 * SECOND]):
            arguments = self.fixture.arguments(); arguments["deadline_monotonic_ns"] = MONO + 60 * SECOND
            self.refused(lambda: custody.verify_original(**arguments))

    def test_expiry_clips_assignment_policy_and_review_pending_ttl(self):
        f = self.fixture
        original = copy.deepcopy(f.statement)
        for field, value in (("expiresAtEpochNs", NOW + 31 * SECOND),
                ("documentExpiresAtEpochNs", NOW + 301 * SECOND), ("issuedAtEpochNs", NOW + 1)):
            f.statement = {**original, field: value}
            self.refused(lambda: self.verify(evidence_original=canonical(f.sign_proof()).decode("ascii")))
        f.statement = original
        f.assignment_payload["expiresAtEpochNs"] = NOW + 29 * SECOND
        f.assignment_original = f.sign_assignment()
        self.refused(lambda: self.verify(evidence_original=canonical(f.sign_proof()).decode("ascii")))

    def test_reservation_ttl_matches_the_exact_policy_not_a_valid_alternative(self):
        # Every changed original is genuinely re-signed and re-encrypted. The
        # only mismatch is the release's 15-second reservation vs this policy.
        self.fixture = Fixture(self.pki, reservation_ttl=16)
        self.refused(lambda: self.verify())

    def test_configuration_cannot_change_during_cryptographic_verification(self):
        f = self.fixture
        def sampled_wall():
            f.configuration["roles"]["planner"]["extraPublicScope"] = "changed after quote verification"
            return NOW
        samples = iter((False, True))
        def wall():
            return sampled_wall() if next(samples) else NOW
        with patch.object(custody.time, "time_ns", side_effect=wall), \
                patch.object(custody.time, "monotonic_ns", return_value=MONO):
            self.refused(lambda: custody.verify_original(**f.arguments()))

    def test_inputs_are_not_rewritten_or_returned_as_transferable_authority(self):
        f = self.fixture
        before = canonical({"configuration": f.configuration, "proof": f.proof,
            "runtime": f.runtime, "parent": f.parent, "child": f.child, "pair": f.pair})
        self.assertIsNone(self.verify())
        self.assertEqual(before, canonical({"configuration": f.configuration, "proof": f.proof,
            "runtime": f.runtime, "parent": f.parent, "child": f.child, "pair": f.pair}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
