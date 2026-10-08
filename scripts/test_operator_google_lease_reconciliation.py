#!/usr/bin/env python3
"""Bounded, network-none proof-protocol tests with real cold admission and DB.

These fixtures directly provision an encrypted synthetic Google grant and
advance it with the real CAS writer. They prove neither provider consent nor
expired-token refresh. Actual signatures/encryption, catalog joins, policy,
nonce storage and the local ASGI endpoint are not replaced for acceptance.
Fault-only patches below test refusal boundaries, never capability admission.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
import uuid

import test_operator_demo_persistence as common
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
PATH = "/api/data-plane/credential-leases"
TOKEN = "synthetic-google-reconciliation-data-plane-token"
BINARY = "sha256:" + "7" * 64
ACCESS = "synthetic-google-reconciliation-access-token"
REFRESH = "synthetic-google-reconciliation-refresh-token"
CLIENT_SECRET = "synthetic-google-reconciliation-client-secret"
UNCONTROLLED = {"controlled": False, "issuanceKind": None, "requestAuthority": None,
    "requestAuthoritySha256": None, "releaseAuthorization": None}
PROOF_KEYS = {"apiVersion", "capability", "profileBindingSha256", "outcome", "reason", "purpose",
    "requestBodySha256", "requestBindingSha256", "policyHash", "scope", "dataPlaneBinaryDigest",
    "recipientKeyId", "recipientNonceSha256", "expectedCredentialVersion", "expectedMetadataSha256",
    "observedCredentialVersion", "observedMetadataSha256", "issuedAtEpochMs", "expiresAtEpochMs"}


class Fixture:
    def __init__(self, *, google=True):
        self.config, self.db, self.store, self.bundles, self.schema, inputs, mutations = workspace.workspace()
        from serverware import app, response_identity, operator_google_lease_reconciliation as proof
        # Import only after the real cold environment has been admitted.
        import test_credential_lease_delivery as delivery
        from cryptography.hazmat.primitives import serialization
        self.app, self.proof, self.delivery = app, proof, delivery
        self.profile = None
        if google:
            from serverware import operator_catalog_oauth_profile as profiles
            self.profile = profiles.require_lease_reconciliation_profile()
            intent = str(uuid.uuid4())
            self.metadata = {"oauth": True, "refreshable": True, "provider_id": "google",
                "provider": "google.oauth2", "provider_subject": "synthetic-google-subject",
                "provider_account": "synthetic-google@example.com", "provider_identity_verified": True,
                "oauth_client_id": self.profile.client_id, "scopes": list(self.profile.scopes),
                "injection_field": "access_token", "expires_at_epoch_ms": 4_102_444_800_000,
                "oauth_profile_binding_digest": self.profile.binding_digest, "oauth_intent_id": intent}
            with self.store.operator_publication.exclusive(), closing(self.db.connect()) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                core = self.db.create_credential("Synthetic Google grant", "oauth2", self.secret(1),
                    self.metadata, _connection=conn)
                self.credential = self.schema.save_resource(conn, "credentials", {
                    "id": core["id"], "name": "Synthetic Google grant", "auth_type": "google_oauth",
                    "header_name": "Authorization", "provider_subject": self.metadata["provider_subject"],
                    "provider_account": self.metadata["provider_account"], "oauth_client_id": self.profile.client_id,
                    "scopes": list(self.profile.scopes), "permission_preset": "gmail_readonly",
                    "oauth_profile_binding_digest": self.profile.binding_digest, "oauth_intent_id": intent,
                    "created_at": self.db.iso_now(), "status": "active"}, create=True)
                self.schema.validate_bindings(conn)
                self.schema.advance_revision(conn, self.schema.read_catalog(conn)["revision"])
        else:
            self.credential = workspace.create_credential(self.db, self.store, self.schema, inputs, mutations)["credential"]
            self.metadata = self.db.get_credential(self.credential["id"])["metadata"]
        self.application = workspace.create_application(self.db, self.store, self.schema, inputs, mutations)["application"]
        self.rule = mutations.create_rule(inputs.RuleInput(
            **workspace.review(self.db, self.store, self.schema), name="Synthetic Gmail read",
            application_id=self.application["id"], credential_id=self.credential["id"],
            upstream_url="https://gmail.googleapis.com/gmail/v1/users/me/messages/synthetic"
                if google else "https://api.example.com/v1/items",
            methods=["GET"], response_fields=["id"]), common._ACTOR)["access_rule"]
        workspace.verify_signed(self.config, self.db, self.store, self.bundles)
        self.policy_hash = self.store.get_policy_high_water()["policy_hash"]
        public = response_identity.response_public_key_info()
        self.signing_key = serialization.load_pem_public_key(public["pem"].encode())
        self.signing_key_id = public["spki_sha256"]

    @staticmethod
    def secret(version):
        return json.dumps({"access_token": ACCESS + "-" + str(version), "refresh_token": REFRESH,
            "token_type": "Bearer"}, sort_keys=True, separators=(",", ":"))

    def rotate(self, version=1):
        row, changed = self.db.update_credential_secret_if_version(self.credential["id"],
            expected_version=version, secret=self.secret(version + 1),
            metadata={**self.metadata, "expires_at_epoch_ms": self.metadata["expires_at_epoch_ms"] + version})
        assert changed and row["credential_version"] == version + 1
        self.app.runtime.invalidate_secret_leases(self.credential["id"])
        return row

    def payload(self, expected=None, **overrides):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        private = X25519PrivateKey.generate()
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        nonce = os.urandom(32)
        value = {"apiVersion": "serverware.credentialLeaseRequest/v3",
            "purpose": "generationMetadata" if expected is None else "dispatchSecret",
            "principalId": self.application["principal_id"], "routeId": self.rule["route_id"],
            "credentialId": self.credential["id"], "recipientPublicKey": self.delivery.b64e(public),
            "recipientKeyId": self.delivery.sha256_prefixed(public), "recipientNonce": self.delivery.b64e(nonce),
            "policyHash": self.policy_hash, "dataPlaneBinaryDigest": BINARY, "maxTtlSeconds": 5}
        if expected is not None:
            value.update(expectedCredentialVersion=expected["credentialVersion"],
                expectedMetadataSha256=expected["metadataSha256"])
        value.update(overrides)
        return value, private, nonce

    def send(self, value, *, status=200, response_nonce=None):
        response = self.delivery.app_request(self.app.app, "POST", PATH, payload=value, headers={
            "X-Serverware-Data-Plane-Token": TOKEN,
            "X-Serverware-Response-Nonce": response_nonce or value["recipientNonce"]})
        self.delivery.assert_status(response, status, "isolated operator Google lease")
        self.delivery.verify_response_signature(response, public_key=self.signing_key,
            key_id=self.signing_key_id, method="POST", target=PATH,
            response_nonce=response_nonce or value["recipientNonce"], policy_hash=self.policy_hash)
        return response

    def metadata_lease(self):
        value, private, nonce = self.payload()
        response = self.send(value)
        lease = self.delivery.decrypt_lease(response.json(), recipient_private_key=private,
            recipient_nonce_raw=nonce, request_payload=value)
        entry = lease["credentials"][0]
        assert "secret" not in entry
        return entry

    def spent(self, value):
        assert self.db.credential_lease_nonce_reserved(value["recipientKeyId"],
            self.delivery.sha256_prefixed(self.delivery.b64d(value["recipientNonce"])),
            now_epoch_ms=time.time_ns() // 1_000_000)

    def no_proof(self, response):
        assert response.json().get("apiVersion") != self.proof.API_VERSION
        assert not PROOF_KEYS.intersection(response.json()), "ordinary failure acquired proof fields"


def signed_proof_and_fresh_lease():
    f = Fixture()
    old = f.metadata_lease()
    advanced = f.rotate()
    value, _, nonce = f.payload(old, recipientAttestation=None)
    with patch.object(f.app, "encrypt_credential_lease_envelope",
            wraps=f.app.encrypt_credential_lease_envelope) as encryption:
        response = f.send(value, status=409)
    assert encryption.call_count == 0
    body = response.json()
    assert set(body) == PROOF_KEYS and len(body) == 19
    assert set(body["scope"]) == {"principalId", "routeId", "credentialId"}
    assert body["apiVersion"] == f.proof.API_VERSION and body["capability"] == "operator-google-v1"
    assert body["outcome"] == "noSecretEnvelopeIssued" and body["reason"] == f.proof.REASON
    assert body["purpose"] == "dispatchSecret" and body["policyHash"] == f.policy_hash
    assert body["profileBindingSha256"] == f.profile.binding_digest
    assert body["scope"] == {key: value[key] for key in ("principalId", "routeId", "credentialId")}
    assert body["requestBodySha256"] == f.delivery.sha256_prefixed(f.delivery.canonical_json_bytes(value))
    admitted = f.app.CredentialLeaseRequest.model_validate(value)
    assert body["requestBindingSha256"] == f.app._credential_lease_request_binding_sha256(admitted)
    assert body["recipientKeyId"] == value["recipientKeyId"] and body["dataPlaneBinaryDigest"] == BINARY
    assert body["recipientNonceSha256"] == f.delivery.sha256_prefixed(nonce)
    assert body["expectedCredentialVersion"] == old["credentialVersion"] == 1
    assert body["expectedMetadataSha256"] == old["metadataSha256"]
    assert body["observedCredentialVersion"] == advanced["credential_version"] == 2
    assert body["observedMetadataSha256"] == f.app._credential_lease_metadata_sha256(
        f.app._credential_lease_public_metadata(advanced))
    assert type(body["issuedAtEpochMs"]) is type(body["expiresAtEpochMs"]) is int
    assert 0 < body["expiresAtEpochMs"] - body["issuedAtEpochMs"] <= 5000
    assert response.headers["cache-control"] == "no-store" and len(response.body) <= 16384
    f.spent(value)
    f.no_proof(f.send(value, status=409))
    current = f.metadata_lease()
    assert current["credentialVersion"] == 2 and current["metadataSha256"] == body["observedMetadataSha256"]
    fresh, private, nonce = f.payload(current)
    issued = f.send(fresh)
    lease = f.delivery.decrypt_lease(issued.json(), recipient_private_key=private,
        recipient_nonce_raw=nonce, request_payload=fresh)
    assert json.loads(lease["credentials"][0]["secret"]) == {"access_token": ACCESS + "-2"}
    with closing(f.db.connect()) as conn:
        events = "\n".join(row[0] for row in conn.execute("SELECT event_json FROM audit_events"))
        stored = dict(conn.execute("SELECT * FROM credentials WHERE id=?", (f.credential["id"],)).fetchone())
    assert f.proof.REASON in events and stored["secret_ciphertext"] and stored["encrypted_dek"]
    for secret in (ACCESS, REFRESH, CLIENT_SECRET):
        assert secret not in events and secret.encode() not in response.body
        assert secret not in json.dumps(response.headers)
    return {"signed_proof": True, "original_nonce_spent": True, "fresh_secret_lease": True}


def nonadvancing_conflicts():
    f = Fixture()
    old = f.metadata_lease()
    for expected in ({**old, "metadataSha256": "sha256:" + "0" * 64},
            {**old, "credentialVersion": 2}):
        value, _, _ = f.payload(expected)
        with patch.object(f.app, "encrypt_credential_lease_envelope", wraps=f.app.encrypt_credential_lease_envelope) as encryption:
            f.no_proof(f.send(value, status=409))
        assert encryption.call_count == 0
        f.spent(value)
    return {"same_version_drift_and_lower_observation_refused": 2}


def prepared_snapshot_drift():
    f = Fixture()
    old = f.metadata_lease()
    f.rotate()
    original = f.proof.pre_encryption_generation_conflict
    def advance_again(*args, **kwargs):
        f.rotate(2)
        return original(*args, **kwargs)
    value, _, _ = f.payload(old)
    with patch.object(f.proof, "pre_encryption_generation_conflict", advance_again):
        f.no_proof(f.send(value, status=409))
    f.spent(value)
    assert f.db.get_credential(f.credential["id"])["credential_version"] == 3
    # A stable observation afterward is eligible; the failed attempt did not reset its nonce.
    fresh, _, _ = f.payload(old)
    assert f.send(fresh, status=409).json()["observedCredentialVersion"] == 3
    return {"concurrent_generation_drift_refused": True}


def catalog_binding_refusals():
    f = Fixture()
    old = f.metadata_lease()
    f.rotate()
    mutations = (
        ("operator_catalog_credentials", f.credential["id"], "oauth_intent_id", str(uuid.uuid4())),
        ("operator_catalog_credentials", f.credential["id"], "oauth_profile_binding_digest", "sha256:" + "0" * 64),
        ("operator_catalog_credentials", f.credential["id"], "provider_account", "other@example.com"),
        ("operator_catalog_applications", f.application["id"], "token_expires_at_epoch_ms", 1),
        ("operator_catalog_rules", f.rule["id"], "status", "revoked"),
    )
    for table, identifier, key, replacement in mutations:
        with closing(f.db.connect()) as conn, conn:
            raw = conn.execute("SELECT data_json FROM " + table + " WHERE id=?", (identifier,)).fetchone()[0]
            value = json.loads(raw)
            value[key] = replacement
            conn.execute("UPDATE " + table + " SET data_json=? WHERE id=?", (json.dumps(value), identifier))
        try:
            request, _, _ = f.payload(old)
            f.no_proof(f.send(request, status=503))
            f.spent(request)
        finally:
            with closing(f.db.connect()) as conn, conn:
                conn.execute("UPDATE " + table + " SET data_json=? WHERE id=?", (raw, identifier))
    value, _, _ = f.payload(old)
    assert f.send(value, status=409).json()["outcome"] == "noSecretEnvelopeIssued"
    return {"real_catalog_binding_refusals": len(mutations)}


def eligibility_and_original_capture():
    f = Fixture()
    old = f.metadata_lease()
    f.rotate()
    original = f.proof.pre_encryption_generation_conflict
    checked = []
    def inspect(request, payload, **kwargs):
        exclusions = ({"profile": "native"}, {"profile": "policy-aware"}, {"wrapped": True},
            {"broker": True}, {"refresh_opening": object()}, {"currentness_opening": object()},
            {"claimed_release_authorization": {}}, {"dispatch_authority": {**UNCONTROLLED, "controlled": True}},
            {"prepared_credential": {**kwargs["prepared_credential"], "metadata": None}})
        for change in exclusions:
            assert original(request, payload, **{**kwargs, **change}) is None
        for change in ({"purpose": "generationMetadata"}, {"request_authority": None}):
            assert original(request, payload.model_copy(update=change), **kwargs) is None
        scope_key = f.app._CREDENTIAL_LEASE_ORIGINAL_SCOPE_KEY
        saved = request.scope.pop(scope_key)
        try:
            from fastapi import HTTPException
            try:
                original(request, payload, **kwargs)
            except HTTPException:
                pass
            else:
                raise AssertionError("proof accepted missing original request capture")
        finally:
            request.scope[scope_key] = saved
        checked.append(len(exclusions) + 3)
        return original(request, payload, **kwargs)
    value, _, _ = f.payload(old)
    with patch.object(f.proof, "pre_encryption_generation_conflict", inspect):
        assert f.send(value, status=409).json()["outcome"] == "noSecretEnvelopeIssued"
    assert checked == [12]
    mismatch, _, _ = f.payload(old)
    f.no_proof(f.send(mismatch, status=409, response_nonce=f.delivery.b64e(os.urandom(32))))
    f.spent(mismatch)
    # Commitment-only control: legacy commitment stays unchanged; the new
    # complete-body digest distinguishes public-key/evidence/absent-null changes.
    model = f.app.CredentialLeaseRequest.model_validate(value)
    baseline = f.app._credential_lease_request_binding_sha256(model)
    full = f.delivery.sha256_prefixed(f.delivery.canonical_json_bytes(value))
    for change in ({"recipientAttestation": None}, {"recipientAttestation": {"test": "evidence"}},
            {"recipientPublicKey": f.delivery.b64e(b"x" * 32)}):
        changed = {**value, **change}
        assert f.app._credential_lease_request_binding_sha256(
            f.app.CredentialLeaseRequest.model_validate(changed)) == baseline
        assert f.delivery.sha256_prefixed(f.delivery.canonical_json_bytes(changed)) != full
    return {"helper_exclusions": 12, "response_nonce_bound": True, "old_commitment_unchanged": True}


def post_encryption_and_reservation_failures():
    f = Fixture()
    old = f.metadata_lease()
    encryption = f.app.encrypt_credential_lease_envelope
    def encrypted_then_fail(**kwargs):
        encryption(**kwargs)
        from fastapi import HTTPException
        raise HTTPException(status_code=409, detail="synthetic post-encryption conflict")
    value, _, _ = f.payload(old)
    with patch.object(f.app, "encrypt_credential_lease_envelope", encrypted_then_fail), \
            patch.object(f.proof, "pre_encryption_generation_conflict", wraps=f.proof.pre_encryption_generation_conflict) as proof:
        f.no_proof(f.send(value, status=409))
    assert proof.call_count == 0
    f.spent(value)
    f.rotate()
    value, _, _ = f.payload(old)
    with patch.object(f.db, "reserve_credential_lease_nonce", return_value="capacity"), \
            patch.object(f.proof, "pre_encryption_generation_conflict", wraps=f.proof.pre_encryption_generation_conflict) as proof:
        f.no_proof(f.send(value, status=503))
    assert proof.call_count == 0
    return {"post_encryption_never_authorizes_retry": True, "capacity_never_authorizes_retry": True}


def audit_boundary():
    f = Fixture()
    old = f.metadata_lease()
    f.rotate()
    audit = f.app._record_credential_lease_audit
    observed = []
    def inspect(*args, **kwargs):
        if kwargs.get("reason") == f.proof.REASON:
            with closing(f.db.connect()) as conn:
                conn.execute("PRAGMA busy_timeout=0")
                conn.execute("BEGIN IMMEDIATE")
                conn.rollback()
            observed.append(True)
        return audit(*args, **kwargs)
    value, _, _ = f.payload(old)
    with patch.object(f.app, "_record_credential_lease_audit", inspect):
        assert f.send(value, status=409).json()["outcome"] == "noSecretEnvelopeIssued"
    assert observed == [True]
    def fail_proof_audit(*args, **kwargs):
        if kwargs.get("reason") == f.proof.REASON:
            raise RuntimeError("synthetic proof audit refusal")
        return audit(*args, **kwargs)
    failed, _, _ = f.payload(old)
    with patch.object(f.app, "_record_credential_lease_audit", fail_proof_audit):
        f.no_proof(f.send(failed, status=503))
    f.spent(failed)
    return {"audit_after_snapshot_release": True, "failed_audit_no_proof": True}


def disabled_static_control():
    f = Fixture(google=False)
    from serverware import operator_catalog_oauth_profile as profiles
    assert profiles.selected() is False
    old = f.metadata_lease()
    row, changed = f.db.update_credential_secret_if_version(f.credential["id"], expected_version=1,
        secret=common._PROVIDER_SECRET + "-rotated", metadata=f.metadata)
    assert changed and row["credential_version"] == 2
    f.app.runtime.invalidate_secret_leases(f.credential["id"])
    value, _, _ = f.payload(old)
    f.no_proof(f.send(value, status=409))
    f.spent(value)
    fresh, private, nonce = f.payload(f.metadata_lease())
    response = f.send(fresh)
    lease = f.delivery.decrypt_lease(response.json(), recipient_private_key=private,
        recipient_nonce_raw=nonce, request_payload=fresh)
    assert lease["credentials"][0]["secret"] == common._PROVIDER_SECRET + "-rotated"
    return {"disabled_static_conflict_unchanged": True, "ordinary_dispatch_still_works": True}


OPERATIONS = {name: value for name, value in tuple(globals().items()) if name in (
    "signed_proof_and_fresh_lease", "nonadvancing_conflicts", "prepared_snapshot_drift",
    "catalog_binding_refusals", "eligibility_and_original_capture", "post_encryption_and_reservation_failures",
    "audit_boundary", "disabled_static_control")}


class OperatorGoogleReconciliationTests(unittest.TestCase):
    run_worker = common.OperatorDemoPersistenceTests.run_worker

    def setUp(self):
        common.OperatorDemoPersistenceTests.setUp(self)
        self.environment.update(SERVERWARE_PUBLIC_URL="https://operator.example.com",
            SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN=TOKEN,
            SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST=BINARY,
            SERVERWARE_SECRET_LEASE_TTL_SECONDS="5")
        if self._testMethodName != "test_disabled_static_control":
            secret = Path(self.scratch.name) / "google-client-secret"
            secret.write_text(CLIENT_SECRET, encoding="utf-8")
            secret.chmod(0o600)
            self.environment.update(SERVERWARE_OPERATOR_GOOGLE_PROFILE="operator-google-v1",
                SERVERWARE_OPERATOR_DEMO_UPSTREAMS='["https://api.example.com","https://gmail.googleapis.com"]',
                SERVERWARE_GOOGLE_OAUTH_CLIENT_ID="synthetic-reconciliation.apps.googleusercontent.com",
                SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE=str(secret),
                SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI="https://operator.example.com/api/oauth/callback/google")

    def command(self, operation):
        return [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation]

    def test_signed_proof_and_fresh_lease(self):
        self.run_worker("signed_proof_and_fresh_lease")

    def test_nonadvancing_conflicts(self):
        self.run_worker("nonadvancing_conflicts")

    def test_prepared_snapshot_drift(self):
        self.run_worker("prepared_snapshot_drift")

    def test_catalog_binding_refusals(self):
        self.run_worker("catalog_binding_refusals")

    def test_eligibility_and_original_capture(self):
        self.run_worker("eligibility_and_original_capture")

    def test_post_encryption_and_reservation_failures(self):
        self.run_worker("post_encryption_and_reservation_failures")

    def test_audit_boundary(self):
        self.run_worker("audit_boundary")

    def test_disabled_static_control(self):
        self.run_worker("disabled_static_control")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
