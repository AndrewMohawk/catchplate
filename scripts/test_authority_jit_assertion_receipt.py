#!/usr/bin/env python3
"""Synthetic ES256 receipt-producer controls, not DB/proof/runtime admission.

The fixture signs real assertion bytes with an ephemeral synthetic key. No
verification guard is patched and no successful-verification DTO is supplied.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sys
import unittest

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import authority_jit_assertion_receipt as receipt
from catchplate import authority_transition_core as core
from catchplate.authority_query_read_work import _ValidationWork, QueryReadValidationLimits


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def fixture(*, cross_origin=False):
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_numbers()
    cose = b64(cbor2.dumps({1: 2, 3: -7, -1: 1,
        -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big")}))
    policy = {
        "schema": "catchplate.jitApproverPolicy/v1", "requiredRoles": [],
        "roleMatch": "any", "allowedApproverIds": ["synthetic-approver"],
        "allowAnyApproverId": False, "requireWebAuthn": True, "threshold": 1,
        "credentialPolicy": {
            "allowedCredentialRecordIds": [], "allowedAuthenticatorClasses": ["yubikey"],
            "allowedAaguids": [], "requireAttestationTrusted": True,
            "requiredTrustBundleDigest": None, "minimumTrustBundleSequence": None,
            "rpId": "synthetic.invalid", "origins": ["https://synthetic.invalid"],
            "requireUserPresence": True, "requireUserVerification": True,
            "counterPolicy": "strict", "maxAssertionAgeSeconds": 30,
        },
    }
    policy_json = core.canonical_bytes(policy).decode("ascii")
    policy_digest = core.framed_digest("catchplate.jitApproverPolicy/v1", policy_json.encode("ascii"))
    approval = {
        "id": "synthetic-approval", "principal_id": "synthetic-principal",
        "route_id": "synthetic-route", "credential_id": "synthetic-service-credential",
        "credential_version": 1, "policy_hash": "sha256:" + "1" * 64,
        "request_digest": "sha256:" + "2" * 64, "operation_digest": "sha256:" + "3" * 64,
        "requested_at": now.isoformat(), "expires_at": (now + timedelta(seconds=30)).isoformat(),
        "approver_policy_json": policy_json, "approver_policy_digest": policy_digest,
    }
    challenge_id = "01234567-89ab-4def-8123-456789abcdef"
    payload = {
        "schema": "catchplate.jitApprovalWebAuthnChallenge/v1",
        "approvalRequestId": approval["id"], "approverId": "synthetic-approver",
        "approverPolicyDigest": policy_digest, "decision": "approve",
        "principalId": approval["principal_id"], "routeId": approval["route_id"],
        "credentialId": approval["credential_id"], "credentialVersion": approval["credential_version"],
        "policyHash": approval["policy_hash"], "requestDigest": approval["request_digest"],
        "operationDigest": approval["operation_digest"], "requestedAt": approval["requested_at"],
        "requestExpiresAt": approval["expires_at"], "challengeId": challenge_id,
    }
    challenge = {
        "id": challenge_id, "challenge": "synthetic-random-challenge",
        "challenge_type": "jit-approval", "user_id": "synthetic-approver",
        "scope_key": f"{approval['id']}:{policy_digest}:approve", "approval_request_id": approval["id"],
        "payload_json": core.canonical_bytes(payload).decode("ascii"),
        "created_at": now.isoformat(), "expires_at": approval["expires_at"], "used_at": None,
    }
    credential = {
        "id": "synthetic-credential", "credential_id": "synthetic-credential-wire",
        "user_id": "synthetic-approver", "revoked_at": None, "public_key_cose": cose,
        "aaguid": "synthetic-aaguid", "authenticator_class": "yubikey", "attestation_trusted": 1,
        "attestation_trust_bundle_digest": "sha256:" + "4" * 64,
        "attestation_trust_bundle_sequence": 1, "sign_count": 1,
    }
    client = core.canonical_bytes({"type": "webauthn.get", "challenge": challenge["challenge"],
        "origin": "https://synthetic.invalid", "crossOrigin": cross_origin})
    auth = hashlib.sha256(b"synthetic.invalid").digest() + b"\x05" + (2).to_bytes(4, "big")
    signature = key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    assertion = {"id": credential["credential_id"], "type": "public-key", "response": {
        "clientDataJSON": b64(client), "authenticatorData": b64(auth), "signature": b64(signature)}}
    return dict(approval=approval, approver_id="synthetic-approver", policy=policy,
        policy_digest=policy_digest, assertion=assertion, challenge_id=challenge_id,
        credential_record_id=credential["id"], challenge=challenge, credential=credential,
        trust={"bundle_digest": credential["attestation_trust_bundle_digest"], "sequence": 1},
        verified_at=now + timedelta(seconds=1), decision="approve")


class JitAssertionReceiptTests(unittest.TestCase):
    def derive(self, values):
        return receipt.derive_receipt(**values, work=_ValidationWork(QueryReadValidationLimits()))

    def test_real_synthetic_signature_produces_exact_row_without_mutating_originals(self):
        values = fixture()
        originals = copy.deepcopy(values)
        row = self.derive(values)
        self.assertEqual(values, originals)
        self.assertEqual(row["challenge_id"], values["challenge_id"])
        self.assertEqual((row["sign_count_before"], row["sign_count_after"]), (1, 2))
        self.assertEqual((row["user_present"], row["user_verified"]), (1, 1))
        self.assertEqual(row["verified_at"], values["verified_at"].isoformat())
        self.assertEqual(row["assertion_receipt_digest"], self.derive(values)["assertion_receipt_digest"])

    def test_numeric_false_cross_origin_is_rejected_even_with_real_valid_signature(self):
        for value in (0, 0.0):
            with self.subTest(value=repr(value)), self.assertRaises(core.TransitionKernelError):
                self.derive(fixture(cross_origin=value))

    def test_tampered_signature_and_expired_original_are_rejected(self):
        values = fixture()
        values["assertion"]["response"]["signature"] = b64(b"invalid-signature")
        with self.assertRaises(core.TransitionKernelError):
            self.derive(values)
        values = fixture()
        values["verified_at"] += timedelta(seconds=30)
        with self.assertRaises(core.TransitionKernelError):
            self.derive(values)


if __name__ == "__main__":
    unittest.main()
