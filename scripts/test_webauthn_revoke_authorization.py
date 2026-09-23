#!/usr/bin/env python3
"""Local signed-verifier-receipt tests; no DB, enrollment, or hardware proof."""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_transition_core as core
from serverware import authority_webauthn_assertion as admission


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class RevokeAssertionAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        self.identity = {
            "sessionIdentityDigest": digest(b"fixture verifier session"),
            "measurementDigest": digest(b"fixture verifier measurement"),
            "attestationReceiptDigest": digest(b"fixture verifier attestation"),
        }
        self.now = 1_900_000_000_000_000_000
        self.request_digest = digest(b"fixture revoke request")
        self.operation_id = core.framed_digest(
            "serverware.policyAuthorityOperation/v2",
            admission.OPERATION.encode("ascii"),
            self.request_digest.encode("ascii"),
        )
        self.capability_id = digest(b"fixture capability")
        challenge = b"local unit assertion challenge"
        rp_id = "unit.example"
        origin = "https://unit.example"
        authenticator = hashlib.sha256(rp_id.encode()).digest() + bytes([5]) + (3).to_bytes(4, "big")
        client = core.canonical_bytes({
            "type": "webauthn.get",
            "challenge": encoded(challenge),
            "origin": origin,
            "crossOrigin": False,
        })
        # The tested authority is the pinned verifier receipt. These bytes are
        # not presented as a valid physical authenticator signature.
        assertion_signature = b"local unit assertion signature bytes"
        self.evidence = self.sign({
            "operation": admission.OPERATION,
            "operationId": self.operation_id,
            "requestDigest": self.request_digest,
            "capabilityId": self.capability_id,
            "challengeId": "unit-challenge",
            "challengeDigest": digest(b"fixture authoritative challenge"),
            "clientChallengeDigest": digest(challenge),
            "credentialRecordId": "unit-credential-record",
            "credentialId": "unit-credential",
            "credentialPolicyDigest": digest(b"fixture credential policy"),
            "authenticatorDataBase64url": encoded(authenticator),
            "authenticatorDataDigest": digest(authenticator),
            "clientDataJSONBase64url": encoded(client),
            "clientDataJSONDigest": digest(client),
            "signatureBase64url": encoded(assertion_signature),
            "signatureDigest": digest(assertion_signature),
            "rpId": rp_id,
            "rpIdHashDigest": digest(rp_id.encode()),
            "origin": origin,
            "flags": 5,
            "userPresent": True,
            "userVerified": True,
            "priorCounter": 2,
            "counter": 3,
            "trustHighWaterDigest": digest(b"fixture trust high water"),
            "metadataPublicationSequence": 1,
            "verifierSessionIdentityDigest": self.identity["sessionIdentityDigest"],
            "verifierMeasurementDigest": self.identity["measurementDigest"],
            "verifierAttestationReceiptDigest": self.identity["attestationReceiptDigest"],
            "verifiedAtEpochNs": self.now - 1_000_000_000,
            "expiresAtEpochNs": self.now + 60_000_000_000,
        })

    def sign(self, value: dict, key: Ed25519PrivateKey | None = None) -> dict:
        result = {name: item for name, item in value.items() if name not in {
            "verifiedAssertionReceiptDigest", "verifierSignatureBase64url", "verifierSignatureDigest",
        }}
        receipt = core.framed_digest(admission.RECEIPT_DOMAIN, core.canonical_bytes(result))
        signature = (key or self.key).sign(receipt.encode("ascii"))
        return {**result, "verifiedAssertionReceiptDigest": receipt,
                "verifierSignatureBase64url": encoded(signature), "verifierSignatureDigest": digest(signature)}

    def verify(self, evidence: dict, **overrides):
        arguments = {
            "operation_id": self.operation_id,
            "request_digest": self.request_digest,
            "capability_id": self.capability_id,
            "verifier_identity": self.identity,
            "verifier_public_key": self.key.public_key(),
            "now_epoch_ns": self.now,
            "deadline_epoch_ns": self.now + 120_000_000_000,
            "maximum_age_ns": 300_000_000_000,
        }
        arguments.update(overrides)
        return admission.verify_revoke_assertion_evidence(evidence, **arguments)

    def test_valid_pinned_receipt_returns_immutable_independent_snapshot(self) -> None:
        verified = self.verify(self.evidence)
        self.assertEqual(dict(verified), self.evidence)
        self.evidence["credentialRecordId"] = "changed-after-verification"
        self.assertEqual(verified["credentialRecordId"], "unit-credential-record")
        with self.assertRaises(TypeError):
            verified["counter"] = 99

    def test_another_signer_cannot_self_assert_the_pinned_identity(self) -> None:
        other = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(admission.AssertionEvidenceError, "signature"):
            self.verify(self.sign(self.evidence, other))
        with self.assertRaisesRegex(admission.AssertionEvidenceError, "signature"):
            self.verify(self.evidence, verifier_public_key=other.public_key())

    def test_pinned_identity_and_request_bindings_are_independent(self) -> None:
        for field in ("operationId", "requestDigest", "capabilityId", "verifierSessionIdentityDigest", "verifierMeasurementDigest", "verifierAttestationReceiptDigest"):
            with self.subTest(field=field):
                changed = self.sign({**self.evidence, field: digest(b"different binding")})
                with self.assertRaises(admission.AssertionEvidenceError):
                    self.verify(changed)

    def test_missing_pin_or_nonclosed_evidence_is_rejected(self) -> None:
        for changed in ({**self.evidence, "unexpected": True}, {name: value for name, value in self.evidence.items() if name != "origin"}):
            with self.assertRaises(admission.AssertionEvidenceError):
                self.verify(changed)
        with self.assertRaises(admission.AssertionEvidenceError):
            self.verify(self.evidence, verifier_public_key=None)

    def test_stale_future_and_unbounded_lifetimes_are_rejected(self) -> None:
        for update in (
            {"expiresAtEpochNs": self.now},
            {"verifiedAtEpochNs": self.now + 1},
            {"expiresAtEpochNs": self.now + 121_000_000_000},
            {"verifiedAtEpochNs": self.now - 301_000_000_000},
        ):
            with self.subTest(update=update), self.assertRaises(admission.AssertionEvidenceError):
                self.verify(self.sign({**self.evidence, **update}))

    def test_presence_verification_counters_and_integer_types_are_required(self) -> None:
        for field, value in (
            ("userPresent", False), ("userVerified", False), ("flags", 1),
            ("counter", 2), ("priorCounter", True), ("counter", True),
            ("metadataPublicationSequence", 0), ("verifiedAtEpochNs", True),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(admission.AssertionEvidenceError):
                self.verify(self.sign({**self.evidence, field: value}))

    def test_receipt_and_signed_raw_byte_digests_are_exact(self) -> None:
        for field in ("authenticatorDataDigest", "clientDataJSONDigest", "signatureDigest", "rpIdHashDigest", "clientChallengeDigest"):
            with self.subTest(field=field), self.assertRaises(admission.AssertionEvidenceError):
                self.verify(self.sign({**self.evidence, field: digest(b"different bytes")}))
        for field in ("verifiedAssertionReceiptDigest", "verifierSignatureDigest"):
            with self.subTest(field=field), self.assertRaises(admission.AssertionEvidenceError):
                self.verify({**self.evidence, field: digest(b"different receipt")})

    def test_canonical_encoding_and_client_ceremony_are_preserved(self) -> None:
        with self.assertRaises(admission.AssertionEvidenceError):
            self.verify(self.sign({**self.evidence, "signatureBase64url": self.evidence["signatureBase64url"] + "="}))
        client = json.loads(base64.urlsafe_b64decode(self.evidence["clientDataJSONBase64url"] + "=="))
        for update in ({"crossOrigin": True}, {"type": "webauthn.create"}, {"origin": "https://other.example"}):
            changed = core.canonical_bytes({**client, **update})
            evidence = self.sign({**self.evidence, "clientDataJSONBase64url": encoded(changed), "clientDataJSONDigest": digest(changed)})
            with self.subTest(update=update), self.assertRaises(admission.AssertionEvidenceError):
                self.verify(evidence)

    def test_source_wiring_keeps_verification_before_db_and_replay(self) -> None:
        # Transparent source-order check while the separate registry startup
        # blocker prevents importing/running the whole authority service.
        planner = (ROOT / "serverware/authority_planner.py").read_text()
        derive = planner.split("    def derive(self, request:", 1)[1].split("class PlannerPersistence:", 1)[0]
        self.assertLess(derive.index("self.verify_assertion_evidence(request)"), derive.index("psycopg.connect("))
        service = (ROOT / "serverware/authority_service.py").read_text()
        handle = service.split("    def _handle_plan(", 1)[1].split("    def ", 1)[0]
        self.assertLess(handle.index("planner.verify_assertion_evidence(planner_request)"), handle.index('"read-persisted-plan"'))
        self.assertIn('verifier_config["signingPublicKeyBase64Url"]', handle)
        self.assertIn('_canonical(derived["webauthnEvidence"])', handle)


if __name__ == "__main__":
    unittest.main()
