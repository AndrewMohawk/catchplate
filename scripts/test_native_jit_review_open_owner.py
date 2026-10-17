#!/usr/bin/env python3
"""Real opening crypto and FD3 dispatch with synthetic retained dependencies.

The fixtures use real Ed25519, locally signed Nitro-shaped COSE/certificates,
AES-GCM and X25519. Only clocks, broker bootstrap and transport are synthetic;
no successful authorization/signature/attestation verdict is substituted. These
tests do not establish hardware, current database roots, browser TLS, commit
ACK delivery, provider access or deployed disclosure.
"""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_violations = []


def no_external_effects(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {
            "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        _violations.append(event)
        raise AssertionError("opening component forbids external effects")


if __name__ == "__main__":
    os.environ["CATCHPLATE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "dev"
    sys.addaudithook(no_external_effects)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from scripts import test_authority_native_jit_retained_history as historical
from scripts import test_authority_native_jit_review_custody as crypto
from catchplate import authority_contract as contract
from catchplate import authority_native_jit_review_assignment as grammar
from catchplate import authority_native_jit_review_open_contract as wire
from catchplate import authority_native_jit_review_open_custody as custody
from catchplate import native_jit_review_material as material
from catchplate import native_jit_review_owner as sealing
from catchplate import native_jit_review_open_owner as native
from catchplate import native_secret_broker_helper as dispatcher

SECOND = 1_000_000_000
NOW, BOOT = crypto.NOW + 90 * SECOND, 500 * SECOND
canonical, sha, encoded = crypto.canonical, crypto.sha256, crypto.encoded


def key_descriptor(key):
    return {"keyId": sha(crypto.public_spki(key)), "publicKeyBase64Url": encoded(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))}


class Channel:
    def __init__(self, clock):
        self.clock, self.deadline = clock, BOOT + 300 * SECOND
        self.messages, self.deadlines = [], []
        self.failure, self.after_reply = None, None
        self.closed = False
        self.socket = SimpleNamespace(close=self.close)

    def close(self):
        self.closed = True

    def check(self, deadline=None):
        if self.clock.boot >= min(self.deadline, self.deadline if deadline is None else deadline):
            raise ValueError("synthetic expired channel")

    def send(self, value, deadline=None):
        self.check(deadline)
        self.messages.append(copy.deepcopy(value)); self.deadlines.append(deadline)
        if value.get("apiVersion") == native.OUTPUT:
            if self.after_reply is not None:
                self.after_reply()
            if self.failure is not None:
                raise self.failure


class Broker:
    # Exercise the real completed-service-token fence, not a supplied verdict.
    require_owner_configuration = dispatcher._Broker.require_owner_configuration

    def __init__(self, channel):
        self.channel, self.kek, self.rsa = channel, AESGCM(crypto.KEY), None
        self.commitment, self.key_id = sha(crypto.KEY), crypto.KEY_ID
        self.service_tokens_opened, self.completed_service_operation_id = True, "synthetic-service-operation"
        self.operations = {self.completed_service_operation_id}
        self.jit_configuration_closed = False
        self.historical_keys = None
        for name in ("refresh", "cleanup", "pending_retirement", "capture_retirement", "exchange", "setup",
                "reconnect", "succession", "static_credential", "static_credential_rotation", "jit_review", "jit_review_open"):
            setattr(self, name + "_owner", None)


class Fixture:
    def __init__(self, pki, retained, *, capacity=2):
        self.pki, self.retained = pki, retained
        self.clock = SimpleNamespace(wall=NOW, boot=BOOT)
        self.channel = Channel(self.clock); self.broker = Broker(self.channel)
        self.root, self.assignment_key, self.grant_key, self.ack_key, self.role = [
            ed25519.Ed25519PrivateKey.from_private_bytes(bytes([number]) * 32)
            for number in (31, 32, 33, 34, 35)]
        self.native = retained.native
        self.selected = copy.deepcopy(retained.selected)
        self.policy = {"schema": custody.SCHEMA, "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "deploymentId": "synthetic-opening", "operationMaxSeconds": 30, "attemptCapacity": capacity,
            "assignmentAuthorizer": crypto.key_descriptor(self.assignment_key), "target": copy.deepcopy(retained.target),
            "authorizerKey": key_descriptor(self.grant_key), "commitOwnerKey": key_descriptor(self.ack_key),
            "nativeOrigin": "https://native.synthetic.invalid", "portalOrigin": "https://portal.synthetic.invalid",
            "trustRoots": {"apiVersion": custody.TRUST_SCHEMA,
                "awsNitroRootCertificatesPem": [pki.root.public_bytes(serialization.Encoding.PEM).decode("ascii")],
                "awsNitroCrlsDerBase64url": [], "nitroCertificateProfile": {
                    "profileId": "aws-nitro-attestation-pki-native-v1", "allowedLeafExtendedKeyUsageOids": []}}}
        self.configuration = {"schema": "catchplate.policyAuthorityServiceConfiguration/v6",
            "roles": {"planner": {"enabledOperations": list(wire.OPERATIONS),
                "responseSigningSpkiDigest": sha(crypto.public_spki(self.role))}}, custody.FIELD: self.policy}
        self.configuration_digest = crypto.framed(self.configuration["schema"], canonical(self.configuration))
        self.assignment = {"schema": custody.ASSIGNMENT_SCHEMA,
            "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": self.configuration_digest,
            "deploymentId": self.policy["deploymentId"], "assignment": self.selected,
            "issuedAtEpochNs": NOW - SECOND, "expiresAtEpochNs": NOW + 120 * SECOND}
        self.assignment_original = self.sign_assignment()
        self.config = {"apiVersion": native.CONFIG, "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": self.configuration_digest, "policy": self.policy,
            "assignmentOriginal": self.assignment_original}
        self.configure_command = {"apiVersion": native.CHANNEL, "phase": "configure", "configuration": self.config}
        self.seal_configure_command = {"apiVersion": sealing.CHANNEL, "phase": "configure",
            "configuration": {"apiVersion": sealing.CONFIG,
                "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
                "controlPlaneConfigurationDigest": self.configuration_digest,
                "deploymentId": "synthetic-opening", "instanceId": self.selected["instanceId"],
                "secretKekId": crypto.KEY_ID, "attemptCapacity": 2,
                "identity": {name: self.selected[name] for name in custody.IDENTITY_FIELDS}}}
        self.recipient = x25519.X25519PrivateKey.from_private_bytes(bytes([41]) * 32)
        self.challenge = {"schema": wire.CHALLENGE_SCHEMA, "reviewId": "synthetic-review-1",
            "approvalRequestId": retained.approval["id"], "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": self.configuration_digest,
            "openingAssignmentSha256": sha(self.assignment_original.encode("ascii")),
            "ownerScopeDigest": sha(canonical(self.config)),
            "identity": {**{name: self.selected[name] for name in custody.IDENTITY_FIELDS},
                "browserCertificateSha256": sha(b"synthetic native TLS leaf"),
                "browserPublicKeySpkiSha256": sha(b"synthetic native TLS SPKI")},
            "nativeOrigin": self.policy["nativeOrigin"], "portalOrigin": self.policy["portalOrigin"],
            "browserNonceCommitment": sha(b"synthetic browser cookie"),
            "recipientPublicKey": encoded(self.recipient.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            "challenge": encoded(b"q" * 32), "issuedAtEpochNs": NOW, "expiresAtEpochNs": NOW + 20 * SECOND}
        self.scope = {name: self.challenge[name] for name in native._CHALLENGE_JOINS}
        self.scope.update(reviewerId="synthetic-reviewer", sessionId="synthetic-session",
            credentialRecordId="synthetic-bound-credential", challengeSha256=sha(b"placeholder"),
            parentOriginalSha256=sha(retained.row["parent_request_original"].encode()),
            childOriginalSha256=sha(retained.row["child_request_original"].encode()), pairSha256=retained.row["pair_sha256"],
            sealProofSha256=retained.row["proof_sha256"], sealedSourceContractDigest=historical.MANIFEST,
            documentExpiresAtEpochNs=retained.scope["documentExpiresAtEpochNs"],
            approvalExpiresAtEpochNs=retained.scope["documentExpiresAtEpochNs"],
            sessionExpiresAtEpochNs=NOW + 60 * SECOND, assignmentExpiresAtEpochNs=self.assignment["expiresAtEpochNs"])
        self.grant = {"schema": wire.AUTHORIZATION_SCHEMA, "operation": wire.AUTHORIZE,
            "requestDigest": sha(b"synthetic authenticated current read"), "scope": self.scope,
            "currentRootVectorDigest": sha(b"synthetic current root vector"),
            "currentRootHeadDigest": sha(b"synthetic current root head"), "currentRootSequence": 42,
            "issuedAtEpochNs": NOW, "expiresAtEpochNs": NOW + 15 * SECOND}
        self.command = {"apiVersion": native.CHANNEL, "phase": "prepare", "deadlineBoottimeNs": BOOT + 25 * SECOND,
            **{wire_name: retained.row[column] for wire_name, column in (
                ("parentOriginal", "parent_request_original"), ("childOriginal", "child_request_original"),
                ("pairOriginal", "pair_original"), ("evidenceOriginal", "proof_original"))}}
        self.refresh()

    def sign_assignment(self, *, key=None, domain=None):
        signature = (key or self.assignment_key).sign(crypto.framed(domain or custody.SIGNED_ASSIGNMENT_SCHEMA,
            canonical(self.assignment)).encode("ascii"))
        return canonical({"schema": custody.SIGNED_ASSIGNMENT_SCHEMA, "payload": self.assignment,
            "signature": encoded(signature)}).decode("ascii")

    def sign_native(self, statement, *, purpose="challenge", nonce_domain=None):
        raw = canonical(statement)
        signature = self.native.sign(statement["schema"].encode("ascii") + b"\0" + raw)
        key = self.native.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        boot = hashlib.sha256(b"catchplate/native-proof-custody-boot/v1\0" + b"b" * 32
            + bytes.fromhex(self.selected["keyId"][7:])
            + bytes.fromhex(self.selected["controlPlaneResponseSigningKeyId"][7:])).digest()
        user_data = b"catchplate/enclave-runtime-key-binding/v1\0\x04" + b"".join(
            bytes.fromhex(self.selected[name][7:]) for name in crypto.QUOTE_SCOPE_FIELDS) + hashlib.sha256(key).digest() + boot
        domain = nonce_domain or ("catchplate/native-jit-review-open-" + purpose + "-attestation/v1").encode() + b"\0"
        quote = self.pki.quote(public_key=key, user_data=user_data,
            nonce=hashlib.sha256(domain + hashlib.sha256(raw).digest() + signature).digest(),
            pcrs=self.selected["expectedPcrs"], now=NOW)
        return canonical({"statement": statement, "signature": "ed25519:" + encoded(signature),
            "nativeKeyEvidence": {"apiVersion": "catchplate.nativeResponseProofKeyEvidence/v1",
                "responseProofPublicKey": encoded(key), "attestationDocumentB64": encoded(quote)},
            "assignmentOriginal": self.assignment_original}).decode("ascii")

    def sign_grant(self, *, key=None, domain=None):
        return canonical({"schema": "catchplate.signedNativeJitReviewOpeningAuthorization/v1",
            "payload": self.grant, "signatureBase64Url": encoded((key or self.grant_key).sign(
                (domain or wire.AUTHORIZATION_SCHEMA.encode() + b"\0") + canonical(self.grant)))}).decode()

    def refresh(self):
        self.command["challengeOriginal"] = self.sign_native(self.challenge)
        self.scope["challengeSha256"] = sha(self.command["challengeOriginal"].encode())
        self.command["authorizationOriginal"] = self.sign_grant()

    def configure_seal(self):
        with patch.object(native.time, "time_ns", side_effect=lambda: self.clock.wall), \
                patch.object(native.time, "clock_gettime_ns", side_effect=lambda _clock: self.clock.boot):
            self.broker.jit_review_owner = sealing.Owner(self.broker, self.seal_configure_command)
            self.channel.messages.clear(); self.channel.deadlines.clear()

    def configure_open(self):
        with patch.object(native.time, "time_ns", side_effect=lambda: self.clock.wall), \
                patch.object(native.time, "clock_gettime_ns", side_effect=lambda _clock: self.clock.boot):
            self.owner = native.Owner(self.broker, self.configure_command)
            self.broker.jit_review_open_owner = self.owner
        return self.owner

    def configure(self):
        self.configure_seal()
        return self.configure_open()

    def decrypt(self):
        result = self.channel.messages[-1]
        aad = native.DOMAIN + bytes.fromhex(sha(canonical(self.command))[7:])
        shared = self.recipient.exchange(x25519.X25519PublicKey.from_public_bytes(
            grammar.decoded(result["serverEphemeralPublicKey"], 32, 32)))
        key = HKDF(algorithm=hashes.SHA256(), length=32,
            salt=grammar.decoded(self.challenge["challenge"], 32, 32), info=aad).derive(shared)
        return AESGCM(key).decrypt(grammar.decoded(result["aeadNonce"], 12, 12),
            grammar.decoded(result["ciphertext"], material.MAX_PRIVATE_BYTES + 16), aad)


class OpeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = crypto.SyntheticNitro()
        cls.retained = historical.Fixture(cls.pki)

    def setUp(self):
        self.f = Fixture(self.pki, self.retained)

    def tearDown(self):
        self.assertEqual(_violations, [])

    def refuse(self):
        f = self.f
        with patch.object(material, "open_release_pair", side_effect=AssertionError("plaintext reached")) as opened:
            with self.assertRaisesRegex(native.OwnerError, "^native JIT review opening is unavailable$"):
                f.owner.handle(f.command)
            opened.assert_not_called()
        self.assertTrue(f.owner._poisoned)
        self.assertEqual(len(f.channel.messages), 1)

    def test_real_grant_quote_and_both_docs_then_only_recipient_redacted_ciphertext(self):
        f = self.f; f.configure(); before = canonical(f.command)
        f.owner.handle(f.command)
        self.assertEqual(f.decrypt(), canonical(self.retained.documents["redacted_display"]))
        self.assertEqual(canonical(f.command), before)
        self.assertEqual(set(f.channel.messages[-1]), {"apiVersion", "requestSha256", "recipientPublicKey",
            "serverEphemeralPublicKey", "aeadNonce", "ciphertext"})
        self.assertEqual(f.channel.deadlines[-1], BOOT + 15 * SECOND)
        self.assertEqual(f.owner._spent_reviews, {f.challenge["reviewId"]})
        self.assertIsNone(f.owner.operation)
        self.assertLess(self.retained.assignment_payload["expiresAtEpochNs"], NOW)
        self.assertLess(self.retained.scope["sealExpiresAtEpochNs"], NOW)
        self.assertNotIn(canonical(self.retained.documents["canonical_request"]), canonical(f.channel.messages))

    def test_bad_signature_wrong_purpose_and_generic_response_key_never_decrypt(self):
        for key, domain in ((self.f.role, None), (self.f.ack_key, None),
                (self.f.grant_key, b"catchplate.generic-response/v1\0")):
            with self.subTest(domain=domain):
                self.f = Fixture(self.pki, self.retained); self.f.configure()
                self.f.command["authorizationOriginal"] = self.f.sign_grant(key=key, domain=domain)
                self.refuse()

    def test_each_literal_altered_after_authorization_never_decrypts(self):
        for field in native._LITERAL_HASHES:
            with self.subTest(field=field):
                self.f = Fixture(self.pki, self.retained); self.f.configure()
                self.f.command[field] += " "
                self.refuse()

    def test_signed_scope_mismatch_never_decrypts(self):
        for field in ("approvalRequestId", "ownerScopeDigest", "recipientPublicKey", "browserNonceCommitment",
                "documentExpiresAtEpochNs", "assignmentExpiresAtEpochNs", "sealedSourceContractDigest"):
            with self.subTest(field=field):
                self.f = Fixture(self.pki, self.retained); f = self.f; f.configure()
                f.scope[field] = f.scope[field] + 1 if type(f.scope[field]) is int else (
                    encoded(b"x" * 32) if field == "recipientPublicKey" else sha(b"different"))
                f.command["authorizationOriginal"] = f.sign_grant()
                self.refuse()

    def test_native_quote_wrong_purpose_never_decrypts(self):
        f = self.f; f.configure()
        f.command["challengeOriginal"] = f.sign_native(f.challenge,
            nonce_domain=b"catchplate/native-release-jit-review-attestation/v1\0")
        f.scope["challengeSha256"] = sha(f.command["challengeOriginal"].encode())
        f.command["authorizationOriginal"] = f.sign_grant()
        self.refuse()

    def test_expired_grant_and_original_shorter_deadline_refuse(self):
        for elapsed, shorter in ((15 * SECOND, False), (2 * SECOND, True)):
            with self.subTest(shorter=shorter):
                self.f = Fixture(self.pki, self.retained); f = self.f; f.configure()
                if shorter:
                    f.command["deadlineBoottimeNs"] = BOOT + SECOND
                f.clock.wall += elapsed; f.clock.boot += elapsed
                self.refuse()

    def test_clock_reversal_or_lifetime_extension_poison(self):
        for field in ("wall", "boot", "channel-deadline"):
            with self.subTest(field=field):
                self.f = Fixture(self.pki, self.retained); f = self.f; f.configure()
                if field == "channel-deadline":
                    f.channel.deadline += SECOND
                else:
                    setattr(f.clock, field, getattr(f.clock, field) - 1)
                self.refuse()

    def test_same_broker_kek_completed_service_and_original_config_required(self):
        for field in ("kek", "channel", "service", "configuration"):
            with self.subTest(field=field):
                self.f = Fixture(self.pki, self.retained); f = self.f; f.configure()
                if field == "kek": f.broker.kek = AESGCM(crypto.KEY)
                elif field == "channel": f.broker.channel = Channel(f.clock)
                elif field == "service": f.broker.completed_service_operation_id = "different"
                else: f.owner.config["policy"]["attemptCapacity"] += 1
                self.refuse()

    def test_service_bootstrap_fences_before_configured_output(self):
        for field in ("service_tokens_opened", "completed_service_operation_id", "operations"):
            with self.subTest(field=field):
                f = Fixture(self.pki, self.retained); f.configure_seal()
                setattr(f.broker, field, {"credential-already-started"} if field == "operations" else None)
                with self.assertRaises(native.OwnerError): f.configure_open()
                self.assertEqual(f.channel.messages, [])

    def test_combined_profile_requires_distinct_live_cold_seal_owner_and_no_other_purpose(self):
        for case in ("missing", "spent", "closed", "other", "identity"):
            with self.subTest(case=case):
                f = Fixture(self.pki, self.retained); f.configure_seal()
                if case == "missing": f.broker.jit_review_owner = None
                elif case == "spent": f.broker.jit_review_owner._spent.add("synthetic-already-sealed")
                elif case == "closed": f.broker.jit_configuration_closed = True
                elif case == "other": f.broker.refresh_owner = object()
                else: f.broker.jit_review_owner.config["identity"]["keyId"] = sha(b"wrong native identity")
                with self.assertRaises(native.OwnerError): f.configure_open()
                self.assertEqual(f.channel.messages, [])

    def test_lost_output_and_cancellation_never_rearm(self):
        class Cancelled(BaseException): pass
        for failure in (OSError("synthetic lost reply"), Cancelled()):
            with self.subTest(error=type(failure).__name__):
                f = Fixture(self.pki, self.retained); f.configure(); f.channel.failure = failure
                with self.assertRaises(native.OwnerError if isinstance(failure, Exception) else Cancelled):
                    f.owner.handle(f.command)
                self.assertTrue(f.owner._poisoned)
                self.assertEqual(f.owner._spent_reviews, {f.challenge["reviewId"]})
                f.channel.failure = None
                with self.assertRaises(native.OwnerError): f.owner.handle(f.command)
                self.assertEqual(len(f.channel.messages), 2)

    def test_replayed_success_never_decrypts_again(self):
        f = self.f; f.configure(); f.owner.handle(f.command)
        with patch.object(material, "open_release_pair", side_effect=AssertionError("replayed decryption")) as opened:
            with self.assertRaises(native.OwnerError): f.owner.handle(f.command)
            opened.assert_not_called()
        self.assertEqual(len(f.channel.messages), 2)

    def test_finite_capacity_and_distinct_recipient_fences_do_not_reset(self):
        for capacity, reuse_recipient in ((1, False), (2, True)):
            with self.subTest(reuse_recipient=reuse_recipient):
                f = Fixture(self.pki, self.retained, capacity=capacity)
                f.configure(); f.owner.handle(f.command)
                f.challenge["reviewId"] = f.scope["reviewId"] = "synthetic-review-2"
                f.challenge["challenge"] = encoded(b"r" * 32)
                if not reuse_recipient:
                    f.recipient = x25519.X25519PrivateKey.from_private_bytes(bytes([42]) * 32)
                    f.challenge["recipientPublicKey"] = f.scope["recipientPublicKey"] = encoded(
                        f.recipient.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
                f.refresh()
                with patch.object(material, "open_release_pair", side_effect=AssertionError("extra decryption")) as opened:
                    with self.assertRaises(native.OwnerError): f.owner.handle(f.command)
                    opened.assert_not_called()
                self.assertEqual(len(f.channel.messages), 2)

    def test_canonical_document_decryption_failure_prevents_view_output(self):
        f = self.f; f.configure()
        real = material.open_release_pair
        def broken(pair, **kwargs):
            changed = copy.deepcopy(pair)
            changed["items"][0]["ciphertext"] = encoded(b"x" * (changed["items"][0]["plaintextBytes"] + 16))
            return real(changed, **kwargs)
        with patch.object(material, "open_release_pair", side_effect=broken):
            with self.assertRaises(native.OwnerError): f.owner.handle(f.command)
        self.assertEqual(len(f.channel.messages), 1)
        self.assertEqual(f.owner._spent_reviews, {f.challenge["reviewId"]})

    def test_cold_policy_keys_independent_from_root_roles_each_other_and_assignment(self):
        f = self.f
        self.assertEqual(custody.validate_policy(f.policy, payload=f.configuration,
            root_key=f.root.public_key()), f.policy)
        for key in (f.root, f.role, f.ack_key, f.assignment_key, f.retained.response):
            with self.subTest(key=key_descriptor(key)["keyId"]):
                changed = copy.deepcopy(f.policy); changed["authorizerKey"] = key_descriptor(key)
                with self.assertRaises(custody.AdmissionError):
                    custody.validate_policy(changed, payload=f.configuration, root_key=f.root.public_key())

    def test_sealing_assignment_cannot_configure_opening(self):
        f = self.f; f.config["assignmentOriginal"] = self.retained.assignment_original
        with self.assertRaises(native.OwnerError): f.configure()
        self.assertEqual(f.channel.messages, [])

    def test_authority_independently_verifies_real_native_challenge(self):
        f = self.f
        with patch.object(custody.time, "time_ns", return_value=NOW), \
                patch.object(custody.time, "monotonic_ns", return_value=BOOT):
            result = custody.verify_native_original(f.command["challengeOriginal"], purpose="challenge",
                configuration_payload=f.configuration, root_key=f.root.public_key(),
                now_epoch_ns=NOW, deadline_monotonic_ns=BOOT + SECOND)
        self.assertEqual(result["statement"], f.challenge)

    def test_authority_independently_verifies_preparation_not_challenge_domain(self):
        f = self.f
        statement = {"schema": wire.PREPARATION_SCHEMA, "operation": wire.PREPARATION_OPERATION,
            "authorizationSha256": sha(f.command["authorizationOriginal"].encode()), "scope": f.scope,
            "identity": f.challenge["identity"], "reviewDigest": sha(canonical(self.retained.documents["redacted_display"])),
            "reviewFormat": wire.REVIEW_FORMAT, "preparedAtEpochNs": NOW + SECOND,
            "expiresAtEpochNs": NOW + 15 * SECOND}
        original = f.sign_native(statement, purpose="preparation")
        with patch.object(custody.time, "time_ns", return_value=NOW + SECOND), \
                patch.object(custody.time, "monotonic_ns", return_value=BOOT + SECOND):
            result = custody.verify_native_original(original, purpose="preparation",
                configuration_payload=f.configuration, root_key=f.root.public_key(),
                now_epoch_ns=NOW + SECOND, deadline_monotonic_ns=BOOT + 2 * SECOND)
            self.assertEqual(result["statement"], statement)
            wrong_domain = f.sign_native(statement, purpose="challenge")
            with self.assertRaises(custody.AdmissionError):
                custody.verify_native_original(wrong_domain, purpose="preparation",
                    configuration_payload=f.configuration, root_key=f.root.public_key(),
                    now_epoch_ns=NOW + SECOND, deadline_monotonic_ns=BOOT + 2 * SECOND)

    def test_strict_command_roster_and_duplicate_outer_json_are_refused(self):
        f = self.f; f.configure(); f.command["verified"] = True
        self.refuse()
        with self.assertRaises(ValueError):
            dispatcher._document(b'{"apiVersion":"one","apiVersion":"two"}')
        self.f = Fixture(self.pki, self.retained); self.f.configure()
        self.f.command["phase"] = "decrypt"
        self.refuse()

    def test_actual_dispatch_selects_separate_channel_and_preserves_seal_numeric_guard(self):
        f = self.f
        queue = iter(({}, {}, f.seal_configure_command, f.configure_command, f.command))
        f.channel.receive = lambda *_args, **_kwargs: next(queue)
        f.broker.provision = lambda value: self.assertEqual(value, {})
        with patch.object(dispatcher, "_Channel", return_value=f.channel), \
                patch.object(dispatcher, "_Broker", return_value=f.broker), \
                patch.object(native.time, "time_ns", side_effect=lambda: f.clock.wall), \
                patch.object(native.time, "clock_gettime_ns", side_effect=lambda _clock: f.clock.boot):
            with self.assertRaises(StopIteration): dispatcher.main()
        self.assertTrue(f.channel.closed)
        self.assertEqual(f.decrypt(), canonical(self.retained.documents["redacted_display"]))
        self.assertIsInstance(f.broker.jit_review_owner, sealing.Owner)
        self.assertIsInstance(f.broker.jit_review_open_owner, native.Owner)
        self.assertEqual(dispatcher._document(canonical(f.command)), f.command)
        for changed in ({**f.command, "deadlineBoottimeNs": 1.5},
                {"apiVersion": "catchplate.nativeJitReviewChannel/v1", "phase": "seal-release-pair"}):
            with self.assertRaises(ValueError): dispatcher._document(canonical(changed))


if __name__ == "__main__":
    unittest.main(verbosity=2)
