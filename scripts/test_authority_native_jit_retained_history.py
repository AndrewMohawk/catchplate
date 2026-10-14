#!/usr/bin/env python3
"""Frozen historical originals, real synthetic sealing, no opening authority.

Requests/rows use literal v349 identities and independent framing, never the
installed manifest or production request/projection builders. Local AES and
Ed25519 run; quote construction uses the existing synthetic PKI fixture.
The history parser is deliberately NOT an attestation verifier. No native
owner, authenticated database root, disclosure, provider or commit is claimed.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_violations = []


def no_external_effects(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {
            "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        _violations.append(event)
        raise AssertionError("historical fixture forbids external effects")


if __name__ == "__main__":
    os.environ["SERVERWARE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
    sys.addaudithook(no_external_effects)

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scripts import test_authority_native_jit_review_custody as crypto
from scripts import test_native_jit_prepare as preparation
from serverware import authority_contract as installed_contract
from serverware import authority_native_jit_retained_history as history
from serverware import native_jit_review_material as material

MANIFEST = "sha256:b708d9f97ca989abf0411054bbc23d02262fb5a67bcab345246650a925e776e0"
REVISION = "serverware.policyCandidateAuthoritySource/2026-07-30.349"
NOW = 1_800_000_000_000_000_000
SECOND = 1_000_000_000
OTHER = "sha256:" + "9" * 64


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def framed(domain, *frames):
    return sha(domain.encode("ascii") + b"\0" + b"".join(
        len(frame).to_bytes(8, "big") + frame for frame in frames))


def request(operation, public, manifest):
    handler = {"release.reserve": "reserve_release_authorization_v2",
        "jit.request": "ensure_jit_approval_request"}[operation]
    arguments = {**copy.deepcopy(public), "businessIntent": {
        "schema": "serverware.policyAuthorityBusinessIntent/v2", "operation": operation,
        "planningAdapterId": "serverware.policyAuthorityPlanningAdapter/" + handler + "/v1",
        "arguments": copy.deepcopy(public)}}
    authorization = {"schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": handler, "operationManifestDigest": manifest, "arguments": arguments}
    digest = framed("serverware.policyAuthorityV9Request/v1", canonical(authorization))
    return {**authorization, "schema": "serverware.policyAuthorityV9Request/v1", "requestDigest": digest,
        "operationId": framed("serverware.policyAuthorityOperation/v2", operation.encode(), digest.encode())}


def identity(digest):
    raw = hashlib.sha256(canonical({"schema": "serverware.policyAuthorityDeterministicIdentity/v1",
        "operation": "jit.request", "requestDigest": digest, "purpose": "jit-approval-request"})).hexdigest()
    value = list(raw[:32]); value[12] = "5"; value[16] = format((int(value[16], 16) & 3) | 8, "x")
    value = "".join(value)
    return "-".join((value[:8], value[8:12], value[12:16], value[16:20], value[20:]))


class Fixture:
    # Only the existing synthetic signing/quote constructors are reused. Its
    # current-manifest constructor is deliberately never invoked.
    sign_assignment = crypto.Fixture.sign_assignment
    sign_proof = crypto.Fixture.sign_proof

    def __init__(self, pki, *, manifest=MANIFEST, operation_context=None, document_tail_ns=0):
        self.pki = pki
        self.authorizer, self.native, self.response = [
            ed25519.Ed25519PrivateKey.from_private_bytes(bytes([number]) * 32) for number in (12, 13, 14)]
        raw = preparation.raw_parent(preparation.payload())
        if operation_context is not None:
            raw["operation_context"] = operation_context
        inherited = {name: raw[name] for name in ("route_id", "principal_id", "credential_id",
            "credential_version", "policy_hash", "request_digest", "operation_digest", "required_approver_roles",
            "allowed_approver_ids", "require_approver_webauthn", "approval_threshold", "approver_credential_policy")}
        original_child = {**inherited, **raw["jit_approval_request"]}
        self.documents = {name: original_child[name] for name in ("url", "canonical_request", "redacted_display")}
        child_public = {name: value for name, value in original_child.items() if name not in self.documents}
        child_public.update(schema="serverware.jitRequestCommitments/v2", original_arguments_digest=sha(canonical(original_child)),
            url_commitment=sha(self.documents["url"].encode()),
            canonical_request_digest=sha(canonical(self.documents["canonical_request"])),
            redacted_display_digest=sha(canonical(self.documents["redacted_display"])))
        parent_public = {**raw, "schema": "serverware.releaseReserveCommitments/v1",
            "original_arguments_digest": sha(canonical(raw)), "jit_approval_request": child_public}
        self.parent = request("release.reserve", parent_public, manifest)
        self.child = request("jit.request", child_public, manifest)
        self.target = {"controlPlaneResponseSigningKeyId": sha(crypto.public_spki(self.response)),
            "releaseRecordSha256": sha(b"historical synthetic release"), "policyHash": raw["policy_hash"],
            "expectedBinaryDigest": sha(b"historical synthetic binary"),
            "expectedPcrs": {"PCR" + str(i): "sha384:" + str(i + 1) * 96 for i in range(3)},
            "expectedEif": "sha384:" + "1" * 96, "maxAgeSeconds": 30, "futureSkewSeconds": 0,
            "instanceId": raw["actor_id"], "secretKekId": crypto.KEY_ID}
        key_id = sha(crypto.public_spki(self.native))
        self.selected = {**self.target, "bootId": crypto.encoded(b"b" * 32), "keyId": key_id,
            "holderId": sha(b"serverware/credential-currentness-holder/v1\0" + b"b" * 32 + bytes.fromhex(key_id[7:])),
            "configurationSha256": sha(b"historical native config"), "caCertificateSha256": sha(b"historical cert"),
            "caPublicKeySpkiSha256": sha(b"historical CA public key"), "expectedModuleId": "synthetic-jit-module"}
        configuration = sha(b"historical independently admitted control plane config")
        self.assignment_payload = {"schema": "serverware.nativeJitReviewAssignment/v1",
            "sourceContractDigest": manifest, "controlPlaneConfigurationDigest": configuration,
            "deploymentId": "synthetic-jit-custody", "assignment": self.selected,
            "issuedAtEpochNs": NOW - SECOND, "expiresAtEpochNs": NOW + 60 * SECOND}
        self.assignment_original = self.sign_assignment()
        self.scope = {"schema": "serverware.nativeJitReviewScope/v2", "publicRequest": self.child,
            "parentRequestSha256": sha(canonical(self.parent)), "sourceContractDigest": manifest,
            "controlPlaneConfigurationDigest": configuration, "ownerScopeDigest": sha(b"historical broker config"),
            "issuedAtEpochNs": NOW, "sealExpiresAtEpochNs": NOW + 30 * SECOND,
            "documentExpiresAtEpochNs": NOW + 299 * SECOND + document_tail_ns}
        self.pair = material.seal_release_pair(self.scope, self.documents,
            key_id=crypto.KEY_ID, kek=AESGCM(crypto.KEY), now_epoch_ns=NOW)
        self.statement = {"apiVersion": "serverware.nativeReleaseJitReviewStatement/v1",
            "operation": "nativeReleaseJitReview.sign/v1", **{name: self.selected[name] for name in crypto.IDENTITY_FIELDS},
            "sourceContractDigest": manifest, "controlPlaneConfigurationDigest": configuration,
            "ownerScopeDigest": self.scope["ownerScopeDigest"], "deploymentId": "synthetic-jit-custody",
            "instanceId": raw["actor_id"], "secretKekId": crypto.KEY_ID,
            "requestDigest": self.child["requestDigest"], "operationId": self.child["operationId"],
            "publicRequestSha256": sha(canonical(self.child)), "pairSha256": sha(canonical(self.pair)),
            "parentRequestSha256": sha(canonical(self.parent)), "parentRequestDigest": self.parent["requestDigest"],
            "parentOperationId": self.parent["operationId"], "challenge": crypto.encoded(b"c" * 32),
            "issuedAtEpochNs": NOW, "expiresAtEpochNs": self.scope["sealExpiresAtEpochNs"],
            "documentExpiresAtEpochNs": self.scope["documentExpiresAtEpochNs"]}
        self.proof = self.sign_proof()
        approval_id = identity(self.child["requestDigest"])
        self.row = {"approval_request_id": approval_id,
            "parent_request_digest": self.parent["requestDigest"], "parent_operation_id": self.parent["operationId"],
            "child_request_digest": self.child["requestDigest"], "child_operation_id": self.child["operationId"],
            **{name + "_original": canonical(value).decode() for name, value in (
                ("parent_request", self.parent), ("child_request", self.child), ("pair", self.pair), ("proof", self.proof))},
            "pair_sha256": sha(canonical(self.pair)), "proof_sha256": sha(canonical(self.proof)),
            "source_contract_digest": manifest, "control_plane_configuration_digest": configuration,
            "owner_scope_digest": self.scope["ownerScopeDigest"], "secret_kek_id": crypto.KEY_ID,
            "issued_at_epoch_ns": NOW, "seal_expires_at_epoch_ns": NOW + 30 * SECOND,
            "document_expires_at_epoch_ns": self.scope["documentExpiresAtEpochNs"],
            "recorded_at_epoch_ns": NOW + SECOND, "source_revision": REVISION}
        policy = preparation.approver_policy()
        policy_digest = framed("serverware.jitApproverPolicy/v1", canonical(policy))
        pending = {"routeId": raw["route_id"], "method": child_public["method"],
            "urlCommitment": child_public["url_commitment"], "principalId": raw["principal_id"],
            "credentialId": raw["credential_id"], "credentialVersion": raw["credential_version"],
            "policyHash": raw["policy_hash"], "requestDigest": raw["request_digest"],
            "operationDigest": raw["operation_digest"], "grantTtlSeconds": child_public["grant_ttl_seconds"],
            "grantMaxUses": child_public["grant_max_uses"], "approverPolicyDigest": policy_digest}
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        self.approval = {"id": approval_id, **{name: child_public[name] for name in (
            "route_id", "method", "principal_id", "credential_id", "credential_version", "policy_hash",
            "request_digest", "operation_digest", "grant_ttl_seconds", "grant_max_uses")},
            "url": child_public["url_commitment"], "status": "pending",
            "requested_at": (epoch + timedelta(microseconds=self.row["recorded_at_epoch_ns"] // 1000)).isoformat(),
            "expires_at": (epoch + timedelta(microseconds=self.scope["documentExpiresAtEpochNs"] // 1000)).isoformat(),
            "pending_key": framed("serverware.jitPendingApproval/v2", canonical(pending)),
            "approver_policy_json": canonical(policy).decode(), "approver_policy_digest": policy_digest,
            **dict.fromkeys(("approved_until", "decision_note", "approved_by", "approval_authn",
                "approver_webauthn_credential_id", "verified_assertion_receipt_digest", "approval_challenge_id"))}
        for name, kind in (("canonical_request", "approval-secret-json/v1"), ("redacted_display", "approval-review-json/v1")):
            self.approval[name] = "native-jit:v1:" + canonical({"schema": "serverware.nativeJitReviewReference/v1",
                "approvalRequestId": approval_id, "parentRequestDigest": self.parent["requestDigest"],
                "pairSha256": self.row["pair_sha256"], "valueKind": kind}).decode()


class HistoricalRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = crypto.SyntheticNitro()
        cls.source = Fixture(cls.pki)

    def setUp(self):
        self.row = copy.deepcopy(self.source.row)
        self.approval = copy.deepcopy(self.source.approval)

    def tearDown(self):
        self.assertEqual(_violations, [], "external effect refusal is not a passing negative")

    def parse(self, *, at=NOW + 90 * SECOND):
        return history.historical_retained_documents(retained_row=self.row,
            approval_row=self.approval, now_epoch_ns=at)

    def refused(self, **kwargs):
        with self.assertRaisesRegex(history.RetainedHistoryError, "^" + history.ERROR + "$") as caught:
            self.parse(**kwargs)
        self.assertIsNone(caught.exception.__cause__)

    def test_actual_synthetic_sealing_and_signature_then_expired_seal_live_documents(self):
        fixture = self.source
        self.assertEqual(material.open_release_pair(fixture.pair, expected_scope=fixture.scope,
            key_id=crypto.KEY_ID, kek=AESGCM(crypto.KEY), now_epoch_ns=NOW + 90 * SECOND), fixture.documents)
        fixture.native.public_key().verify(crypto.assignment.decoded(fixture.proof["signature"][8:], 64, 64),
            b"serverware.nativeReleaseJitReviewStatement/v1\0" + canonical(fixture.statement))
        self.assertEqual(self.parse(), (fixture.parent, fixture.child, fixture.pair, fixture.proof))
        self.assertLess(fixture.assignment_payload["expiresAtEpochNs"], NOW + 90 * SECOND)

    def test_originals_are_unchanged_and_returned_graphs_are_owned(self):
        before = copy.deepcopy((self.row, self.approval))
        parsed = self.parse(); parsed[0]["arguments"]["operation_context"]["label"] = "mutated parsed copy"
        self.assertEqual((self.row, self.approval), before)
        self.assertNotEqual(self.parse()[0], parsed[0])

    def test_explicit_historical_profile_not_installed_manifest_or_request_constructor(self):
        self.assertEqual(self.parse()[0]["operationManifestDigest"], MANIFEST)
        self.assertEqual(history.SEALED_SOURCE_REVISION, REVISION)
        self.assertEqual(history.SEALED_PROFILES, (
            (MANIFEST, REVISION),
            ("sha256:ed6d471a03516c96aa4968b89e4d220f9d5aaa0dfc4c1f848acfcc58343de4f0",
                "serverware.policyCandidateAuthoritySource/2026-07-30.350"),
            ("sha256:bb0f9a53066e10042f83a1576d2c44b1dcf497eee457bb8d3146d86f4d526256",
                "serverware.policyCandidateAuthoritySource/2026-07-30.351"),
        ))
        # This assertion remains meaningful after installed metadata advances;
        # it never patches it or regenerates the fixture with its digest.
        self.assertEqual(self.row["source_contract_digest"], MANIFEST)
        self.assertTrue(installed_contract.OPERATION_MANIFEST_DIGEST.startswith("sha256:"))
        source = inspect.getsource(history)
        self.assertNotIn("contract.OPERATION_MANIFEST_DIGEST", source)
        self.assertNotIn("synthesize_business_intent(", source)
        self.assertNotIn("verify_original(", source)

    def test_fully_joined_future_manifest_pair_is_not_implicitly_admitted(self):
        future = Fixture(self.pki, manifest=OTHER)
        self.row, self.approval = future.row, future.approval
        self.refused()

    def test_unknown_source_revision_and_manifest_are_refused(self):
        for name, value in (("source_revision", REVISION + ".future"), ("source_contract_digest", OTHER)):
            with self.subTest(name=name):
                self.row = copy.deepcopy(self.source.row); self.row[name] = value; self.refused()

    def test_exact_parent_child_hashes_and_all_stored_digest_joins(self):
        for name in ("parent_request_digest", "parent_operation_id", "child_request_digest", "child_operation_id",
                "pair_sha256", "proof_sha256", "owner_scope_digest", "control_plane_configuration_digest"):
            with self.subTest(name=name):
                self.row = copy.deepcopy(self.source.row); self.row[name] = OTHER; self.refused()

    def test_original_bytes_cannot_be_reencoded_or_extended(self):
        for name in ("parent_request_original", "child_request_original", "pair_original", "proof_original"):
            with self.subTest(name=name):
                self.row = copy.deepcopy(self.source.row); self.row[name] += "\n"; self.refused()

    def test_rebound_child_or_parent_argument_cannot_keep_original_identity(self):
        for name in ("parent_request_original", "child_request_original"):
            with self.subTest(name=name):
                self.row = copy.deepcopy(self.source.row)
                value = json.loads(self.row[name]); value["arguments"]["credential_version"] = 8
                self.row[name] = canonical(value).decode(); self.refused()

    def test_pending_approval_and_complete_projection_are_exact(self):
        for name, value in (("status", "approved"), ("url", "https://private.invalid"), ("pending_key", OTHER),
                ("credential_version", True), ("requested_at", self.source.approval["expires_at"]),
                ("expires_at", "2030-01-01T00:00:00+00:00"), ("approved_by", "oidc:other"),
                ("approver_policy_digest", OTHER), ("id", "00000000-0000-5000-8000-000000000000")):
            with self.subTest(name=name):
                self.approval = copy.deepcopy(self.source.approval); self.approval[name] = value; self.refused()

    def test_mixed_malformed_or_cross_pair_references_are_refused(self):
        for name in ("canonical_request", "redacted_display"):
            for value in ("approval:v2:legacy", " Native-jit:v1:{}", self.source.approval[
                    "redacted_display" if name == "canonical_request" else "canonical_request"]):
                with self.subTest(name=name, value=value[:32]):
                    self.approval = copy.deepcopy(self.source.approval); self.approval[name] = value; self.refused()

    def test_original_retention_must_precede_seal_expiry_and_not_be_future(self):
        for value in (NOW - 1000, NOW + 30 * SECOND, NOW + 31 * SECOND, True, NOW + 1):
            with self.subTest(value=value):
                self.row = copy.deepcopy(self.source.row); self.row["recorded_at_epoch_ns"] = value; self.refused()
        self.row = copy.deepcopy(self.source.row); self.refused(at=NOW)

    def test_document_and_approval_expiry_are_not_renewed(self):
        self.assertEqual(self.parse(at=NOW + 299 * SECOND - 1)[2]["scope"], self.source.scope)
        for at in (NOW + 299 * SECOND, NOW + 300 * SECOND, True):
            with self.subTest(at=at): self.refused(at=at)
        self.row["document_expires_at_epoch_ns"] += SECOND; self.refused()

    def test_approval_microsecond_floor_precedes_original_nanosecond_expiry(self):
        fixture = Fixture(self.pki, document_tail_ns=999)
        self.row, self.approval = fixture.row, fixture.approval
        self.parse(at=NOW + 299 * SECOND - 1)
        self.refused(at=NOW + 299 * SECOND)

    def test_statement_and_assignment_originals_cannot_be_substituted(self):
        for name in ("parentRequestSha256", "publicRequestSha256", "ownerScopeDigest", "policyHash"):
            with self.subTest(name=name):
                self.row = copy.deepcopy(self.source.row)
                proof = json.loads(self.row["proof_original"]); proof["statement"][name] = OTHER
                self.row["proof_original"] = canonical(proof).decode()
                self.row["proof_sha256"] = sha(self.row["proof_original"].encode()); self.refused()
        self.row = copy.deepcopy(self.source.row)
        signer = copy.copy(self.source)
        signer.assignment_payload = copy.deepcopy(self.source.assignment_payload)
        signer.assignment_payload["assignment"]["instanceId"] = "spiffe://synthetic.invalid/rebound"
        proof = copy.deepcopy(self.source.proof)
        proof["assignmentOriginal"] = signer.sign_assignment()
        self.row["proof_original"] = canonical(proof).decode()
        self.row["proof_sha256"] = sha(self.row["proof_original"].encode())
        self.refused()

    def test_ciphertext_item_grammar_and_child_opaque_identity_are_exact(self):
        for name, value in (("opaqueId", "00000000-0000-5000-8000-000000000000"),
                ("plaintextBytes", True), ("wrappedKeyNonce", "!"), ("valueKind", "approval-secret-json/v1")):
            with self.subTest(name=name):
                self.row = copy.deepcopy(self.source.row)
                self.approval = copy.deepcopy(self.source.approval)
                pair = json.loads(self.row["pair_original"]); pair["items"][1][name] = value
                self.row["pair_original"] = canonical(pair).decode()
                self.row["pair_sha256"] = sha(self.row["pair_original"].encode())
                # Keep the earlier pair/proof/reference joins valid so each
                # negative reaches its intended item grammar check. Produce
                # a real new synthetic signature and quote, not a verdict.
                signer = copy.copy(self.source)
                signer.statement = copy.deepcopy(self.source.statement)
                signer.statement["pairSha256"] = self.row["pair_sha256"]
                self.row["proof_original"] = canonical(signer.sign_proof()).decode()
                self.row["proof_sha256"] = sha(self.row["proof_original"].encode())
                for field in ("canonical_request", "redacted_display"):
                    reference = json.loads(self.approval[field][len("native-jit:v1:"):])
                    reference["pairSha256"] = self.row["pair_sha256"]
                    self.approval[field] = "native-jit:v1:" + canonical(reference).decode()
                self.refused()

    def test_unknown_row_fields_and_missing_originals_are_refused(self):
        self.row["verified"] = True; self.refused()
        self.row = copy.deepcopy(self.source.row); del self.row["proof_original"]; self.refused()
        self.row = copy.deepcopy(self.source.row); self.approval["opened"] = True; self.refused()

    def test_finite_float_and_large_integer_original_spellings_are_preserved(self):
        fixture = Fixture(self.pki, operation_context={"integer": 2**80, "float": 1.25, "negativeZero": -0.0})
        self.row, self.approval = fixture.row, fixture.approval
        self.assertIn('"integer":1208925819614629174706176', self.row["parent_request_original"])
        self.assertIn('"negativeZero":-0.0', self.row["parent_request_original"])
        self.assertEqual(canonical(self.parse()[0]).decode(), self.row["parent_request_original"])
        self.row["parent_request_original"] = self.row["parent_request_original"].replace('"float":1.25', '"float":1.250')
        self.refused()

    def test_literal_and_escaped_channel_caps_remain_distinct(self):
        original = self.row["parent_request_original"]
        self.row["parent_request_original"] = " " * (512 * 1024 + 1); self.refused()
        self.row["parent_request_original"] = original
        retained = {wire: self.row[column] for wire, column in (
            ("parentOriginal", "parent_request_original"), ("childOriginal", "child_request_original"),
            ("pairOriginal", "pair_original"), ("evidenceOriginal", "proof_original"))}
        self.assertGreater(len(canonical(retained)), sum(len(value) for value in retained.values()))
        self.assertLess(len(canonical(retained)), 4 * 1024 * 1024)
        self.parse()


if __name__ == "__main__":
    unittest.main()
