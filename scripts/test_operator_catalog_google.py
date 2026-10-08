#!/usr/bin/env python3
"""Isolated Google catalog boundary tests; no provider or consent simulation.

Run only in the bounded network-none, read-only-source application harness.
Each subprocess cold-admits the explicit development profile and uses real
SQLite, envelope encryption, catalog transactions and policy signatures. The
fixture inserts synthetic already-verified account metadata: it does NOT prove
Google consent, callback identity verification, refresh, or native authority.
No OAuth lifecycle/profile guards are patched. Gate observation alone is stubbed.
"""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import uuid

import test_operator_demo_persistence as common
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
ACCESS_TOKEN = "synthetic-google-catalog-access-token"
REFRESH_TOKEN = "synthetic-google-catalog-refresh-token"
CLIENT_SECRET = "synthetic-google-catalog-client-secret"
GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me/"


def refused(operation, exception):
    try:
        operation()
    except exception:
        return
    raise AssertionError("Google catalog boundary accepted an invalid binding")


class Fixture:
    def __init__(self):
        (self.config, self.db, self.store, self.bundles, self.schema,
            self.inputs, self.mutations) = workspace.workspace()
        from serverware import operator_catalog_google, operator_catalog_oauth_profile
        self.google, self.profiles = operator_catalog_google, operator_catalog_oauth_profile
        self.profile = self.profiles.require_profile()
        self.initial_policy = self.config.POLICY_BUNDLE_PATH.read_bytes()
        metadata = {
            "oauth": True, "refreshable": True, "provider": "google.oauth2",
            "provider_id": "google", "provider_identity_verified": True,
            "provider_subject": "synthetic-google-account-123",
            "provider_account": "fixture@example.com", "injection_field": "access_token",
            "oauth_client_id": self.profile.client_id, "scopes": list(self.profile.scopes),
            "oauth_profile_binding_digest": self.profile.binding_digest,
            "oauth_intent_id": str(uuid.uuid4()),
        }
        self.secret = json.dumps({"access_token": ACCESS_TOKEN, "refresh_token": REFRESH_TOKEN,
            "token_type": "Bearer", "expires_at": int(time.time()) + 3600,
            "scope": " ".join(self.profile.scopes)}, sort_keys=True)
        # This is fixture construction, not the consent workflow producer. Its
        # synthetic intent identifier is not evidence of a completed callback.
        with self.store.operator_publication.exclusive(), closing(self.db.connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            revision = self.schema.read_catalog(conn)["revision"]
            core = self.db.create_credential("Google fixture account", "oauth2", self.secret,
                metadata, _connection=conn)
            record = {"id": core["id"], "name": core["name"], "status": "active",
                "created_at": core["created_at"], "auth_type": "google_oauth",
                "header_name": "Authorization", "permission_preset": "gmail_readonly",
                **{key: metadata[key] for key in ("provider_subject", "provider_account",
                    "oauth_client_id", "scopes", "oauth_profile_binding_digest", "oauth_intent_id")}}
            self.record = self.schema.save_resource(conn, "credentials", record, create=True)
            self.schema.advance_revision(conn, revision)
            self.schema.validate_bindings(conn)

    def core(self):
        with closing(self.db.connect()) as conn:
            return dict(conn.execute("SELECT * FROM credentials WHERE id=?", (self.record["id"],)).fetchone())

    def snapshot(self):
        value = workspace.snapshot(self.db, catalog=True)
        value["operator_catalog_oauth_profile"] = workspace.rows(self.db, "operator_catalog_oauth_profile")
        return value, self.config.POLICY_BUNDLE_PATH.read_bytes()

    def call(self, operation, *args, **kwargs):
        # No management-network probe is part of these storage/policy tests.
        with patch.object(self.store, "loaded_policy_hash", return_value=None):
            return operation(*args, **kwargs)

    def application(self):
        result = self.call(workspace.create_application, self.db, self.store,
            self.schema, self.inputs, self.mutations)
        return result["application"]

    def rule(self, application, suffix="messages", **changes):
        fields = {"name": "Google read fixture", "application_id": application["id"],
            "credential_id": self.record["id"], "upstream_url": GMAIL + suffix,
            "methods": ["GET"], "response_fields": ["messages", "nextPageToken"]}
        fields.update(changes)
        payload = self.inputs.RuleInput(**workspace.review(self.db, self.store, self.schema), **fields)
        return self.call(self.mutations.create_rule, payload, common._ACTOR)


def encrypted_account():
    f = Fixture()
    core = f.core()
    metadata = f.google.validate_record(f.record, core)
    assert metadata["provider_identity_verified"] is True
    assert all(core[key] for key in ("encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id"))
    assert f.db.get_credential(f.record["id"], include_secret=True)["secret"] == f.secret
    assert f.config.POLICY_BUNDLE_PATH.read_bytes() == f.initial_policy
    assert f.store.get_policy_high_water()["sequence"] == 1
    status = f.call(f.mutations.catalog_status)
    public = status["credentials"][0]
    assert public["auth_type"] == "google_oauth" and public["active_rule_count"] == 0
    assert public["provider_account"] == "fixture@example.com"
    assert public["scopes"] == list(f.profile.scopes) and public["permission_preset"] == "gmail_readonly"
    assert "oauth_intent_id" not in public and "oauth_profile_binding_digest" not in public
    with closing(f.db.connect()) as conn:
        persisted = "\n".join(conn.iterdump())
    for secret in (ACCESS_TOKEN, REFRESH_TOKEN, CLIENT_SECRET):
        assert secret not in persisted and secret not in json.dumps(status)
    assert status["applications"] == status["access_rules"] == []
    return {"encrypted": True, "no_access": True}


def record_guards():
    f = Fixture()
    before = f.snapshot()
    core, record = f.core(), deepcopy(f.record)
    cases = []
    for key, value in {"auth_type": "bearer", "header_name": "X-Api-Key", "status": "revoked",
            "id": str(uuid.uuid4()), "name": "Different account", "provider_subject": "different",
            "provider_account": "different@example.com", "oauth_client_id": "other.apps.googleusercontent.com",
            "permission_preset": "gmail_modify", "oauth_profile_binding_digest": "sha256:" + "0" * 64,
            "oauth_intent_id": "not-a-uuid", "scopes": list(reversed(f.profile.scopes))}.items():
        cases.append(({**record, key: value}, core))
    for key, value in {"kind": "bearer", "lifecycle_status": "revoked", "name": "Replaced core name",
            "metadata": "not-json", "id": str(uuid.uuid4())}.items():
        cases.append((record, {**core, key: value}))
    for key, value in {"oauth": False, "refreshable": False, "provider_identity_verified": False,
            "provider_id": "x", "provider": "operator-demo", "injection_field": "refresh_token",
            "provider_subject": "other", "provider_account": "other@example.com",
            "oauth_client_id": "other.apps.googleusercontent.com", "oauth_intent_id": str(uuid.uuid4()),
            "oauth_profile_binding_digest": "sha256:" + "0" * 64,
            "scopes": [*f.profile.scopes, f.profile.scopes[0]]}.items():
        changed = json.loads(core["metadata"])
        changed[key] = value
        cases.append((record, {**core, "metadata": json.dumps(changed)}))
    cases.append((record, None))
    for candidate, credential in cases:
        refused(lambda: f.google.validate_record(candidate, credential), f.schema.CatalogIntegrityError)
    assert f.snapshot() == before
    return {"refused": len(cases)}


def persisted_tampering():
    f = Fixture()
    before = f.snapshot()
    with closing(f.db.connect()) as conn:
        for column, value in (("kind", "bearer"), ("lifecycle_status", "revoked"), ("metadata", "{}")):
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE credentials SET " + column + "=? WHERE id=?", (value, f.record["id"]))
            refused(lambda: f.schema.validate_bindings(conn), f.schema.CatalogIntegrityError)
            conn.rollback()
        conn.execute("BEGIN IMMEDIATE")
        f.schema.save_resource(conn, "credentials", {**f.record, "oauth_client_id": "other.apps.googleusercontent.com"})
        refused(lambda: f.schema.validate_bindings(conn), f.schema.CatalogIntegrityError)
        conn.rollback()
    assert f.snapshot() == before
    return {"refused": 4}


def profile_pin():
    f = Fixture()
    before = f.snapshot()
    with closing(f.db.connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        f.google.initialize_profile(conn)
        conn.commit()
        assert f.snapshot() == before
        for column, value in (("binding_digest", "sha256:" + "0" * 64), ("binding_json", "{}")):
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE operator_catalog_oauth_profile SET " + column + "=? WHERE singleton=1", (value,))
            refused(lambda: f.google.initialize_profile(conn), f.schema.CatalogIntegrityError)
            conn.rollback()
    assert f.snapshot() == before
    return {"pin_refusals": 2}


def cold_drift():
    f = Fixture()
    before, core = f.snapshot(), f.core()
    changes = {"SERVERWARE_OPERATOR_GOOGLE_PROFILE": "",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": "456-changed.apps.googleusercontent.com",
        "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": "https://control.example.com/other-callback"}
    for key, value in changes.items():
        with patch.dict(os.environ, {key: value}):
            refused(lambda: f.google.validate_record(f.record, core), f.profiles.OperatorGoogleProfileError)
    assert f.snapshot() == before
    f.google.validate_record(f.record, core)
    return {"cold_drift_refusals": len(changes)}


def gmail_policy():
    f = Fixture()
    application = f.application()
    suffixes = ("profile", "history", "messages", "messages/message_123", "threads",
        "threads/thread-123", "labels", "labels/Label_123")
    for suffix in suffixes:
        f.rule(application, suffix)
    signed = workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    expected = {"id": f.record["id"], "credentialType": "oauth2", "provider": "google",
        "providerSubject": f.record["provider_subject"], "oauthClientId": f.profile.client_id,
        "scopes": list(f.profile.scopes),
        "injection": {"type": "bearer", "header": "Authorization", "field": "access_token"}}
    assert signed["credentials"] == [expected]
    assert len(signed["routes"]) == len(suffixes) and len(signed["principals"]) == 1
    for route, suffix in zip(signed["routes"], suffixes):
        assert route["match"]["host"] == "gmail.googleapis.com"
        assert route["match"]["methods"] == ["GET"]
        assert route["match"]["paths"] == ["/gmail/v1/users/me/" + suffix]
        assert route["credentialRef"] == f.record["id"]
        assert route["adapter"]["config"]["credentialBinding"] == {
            "credentialType": "oauth2", "provider": "google",
            "subjects": [f.record["provider_subject"]], "clientIds": [f.profile.client_id],
            "requiredScopes": list(f.profile.scopes)}
    return {"gmail_read_routes": len(suffixes), "signed_oauth2": True}


def invalid_rules():
    f = Fixture()
    application = f.application()
    before = f.snapshot()
    rule = {"upstream_url": GMAIL + "messages", "methods": ["GET"], "request_fields": []}
    invalid = [{**rule, "upstream_url": value} for value in (
        "https://api.example.com/gmail/v1/users/me/messages",
        "https://gmail.googleapis.com/gmail/v1/users/other/messages",
        GMAIL + "messages/id/attachments/id", GMAIL + "messages/",
        GMAIL + "../messages", GMAIL + "%6dessages", GMAIL + "messages?alt=json",
        GMAIL + "messages#fragment", "https://gmail.googleapis.com:443/gmail/v1/users/me/messages")]
    invalid += [{**rule, "methods": ["POST"]}, {**rule, "methods": ["GET", "POST"]},
        {**rule, "request_fields": ["raw"]}]
    for candidate in invalid:
        refused(lambda: f.google.validate_rule(candidate, f.record), f.schema.CatalogIntegrityError)
    for changes in ({"methods": ["POST"]}, {"request_fields": ["raw"]},
            {"upstream_url": "https://api.example.com/v1/items"}):
        refused(lambda: f.rule(application, **changes), (f.schema.CatalogIntegrityError, ValueError))
        assert f.snapshot() == before
    return {"invalid_rules": len(invalid), "mutation_rollbacks": 3}


def static_revoke():
    f = Fixture()
    before = f.snapshot()
    target = workspace.target(f.db, f.store, f.schema, f.inputs, f.record["id"])
    refused(lambda: f.call(f.mutations.revoke_credential, target, common._ACTOR), f.schema.CatalogConflict)
    assert f.snapshot() == before and f.core()["lifecycle_status"] == "active"
    return {"managed_static_delete_refused": True}


def lease_binding():
    f = Fixture()
    application = f.application()
    rule = f.rule(application)["access_rule"]
    arguments = {"principal_id": application["principal_id"], "route_id": rule["route_id"],
        "credential_id": f.record["id"], "core_credential": f.core(), "profile": f.profile}
    before = f.snapshot()
    with closing(f.db.connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        assert f.google.require_lease_binding(conn, **arguments)["id"] == f.record["id"]
        for key, value in (("principal_id", "agent:operator-demo:" + str(uuid.uuid4())),
                ("route_id", "operator." + str(uuid.uuid4())), ("credential_id", str(uuid.uuid4()))):
            refused(lambda: f.google.require_lease_binding(conn, **{**arguments, key: value}),
                f.schema.CatalogIntegrityError)
        conn.rollback()
        for collection, identifier, changes in (
                ("applications", application["id"], {"status": "revoked"}),
                ("applications", application["id"], {"token_expires_at_epoch_ms": 1}),
                ("access_rules", rule["id"], {"status": "revoked"})):
            conn.execute("BEGIN IMMEDIATE")
            record = next(item for item in f.schema.read_catalog(conn)[collection] if item["id"] == identifier)
            f.schema.save_resource(conn, collection, {**record, **changes})
            refused(lambda: f.google.require_lease_binding(conn, **arguments), f.schema.CatalogIntegrityError)
            conn.rollback()
    assert f.snapshot() == before
    return {"read_only_binding": True, "lease_refusals": 6}


def scope_normalization():
    f = Fixture()
    from serverware import operator_catalog_oauth as consent
    canonical = " ".join(f.profile.scopes)
    alias = "https://www.googleapis.com/auth/userinfo.email"
    accepted = (canonical, " ".join(reversed(f.profile.scopes)),
        canonical.replace("email", alias), canonical + " " + alias)
    before = f.snapshot()
    for granted in accepted:
        assert consent.canonical_granted_scopes(granted) == list(f.profile.scopes)
    rejected = ("", "openid email", canonical.replace("gmail.readonly", "gmail.modify"),
        canonical + " https://www.googleapis.com/auth/drive.readonly",
        canonical.replace("email", "https://www.googleapis.com/auth/userinfo.profile"),
        canonical.replace(" ", "  ", 1), canonical + "\n", canonical + " email", None)
    for granted in rejected:
        refused(lambda: consent.canonical_granted_scopes(granted), consent.GoogleConsentError)
    assert f.snapshot() == before
    return {"accepted": len(accepted), "rejected": len(rejected)}


def refresh_association():
    f = Fixture()
    from serverware import operator_catalog_oauth as consent
    metadata = json.loads(f.core()["metadata"])
    before = f.snapshot()
    assert consent.profile_for_refresh(metadata) == f.profile
    for key, value in (("oauth_intent_id", str(uuid.uuid4())),
            ("oauth_profile_binding_digest", "sha256:" + "0" * 64),
            ("provider_subject", "other-account"), ("oauth_client_id", "456-other.apps.googleusercontent.com")):
        refused(lambda: consent.profile_for_refresh({**metadata, key: value}), consent.GoogleConsentError)
    assert f.snapshot() == before
    return {"refresh_metadata_refusals": 4}


OPERATIONS = {"encrypted-account": encrypted_account, "record-guards": record_guards,
    "persisted-tampering": persisted_tampering, "profile-pin": profile_pin,
    "cold-drift": cold_drift, "gmail-policy": gmail_policy, "invalid-rules": invalid_rules,
    "static-revoke": static_revoke, "lease-binding": lease_binding,
    "scope-normalization": scope_normalization, "refresh-association": refresh_association}


class OperatorCatalogGoogleTests(unittest.TestCase):
    def setUp(self):
        common.OperatorDemoPersistenceTests.setUp(self)
        secret_file = Path(self.scratch.name) / "google-client-secret"
        secret_file.write_text(CLIENT_SECRET + "\n", encoding="utf-8")
        secret_file.chmod(0o600)
        self.environment.update({"SERVERWARE_OPERATOR_GOOGLE_PROFILE": "operator-google-v1",
            "SERVERWARE_OPERATOR_DEMO_UPSTREAMS": '["https://api.example.com","https://gmail.googleapis.com"]',
            "SERVERWARE_PUBLIC_URL": "https://control.example.com",
            "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": "123-fixture.apps.googleusercontent.com",
            "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": "https://control.example.com/api/oauth/callback/google",
            "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE": str(secret_file)})

    def run_worker(self, operation):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-40:]))
        return json.loads(result.stdout)

    def test_encrypted_managed_account_is_metadata_only_and_publicly_redacted(self):
        self.assertTrue(self.run_worker("encrypted-account")["no_access"])

    def test_exact_account_client_scope_intent_and_active_core_bindings(self):
        self.assertEqual(self.run_worker("record-guards")["refused"], 30)

    def test_actual_core_and_catalog_row_tampering_is_refused(self):
        self.assertEqual(self.run_worker("persisted-tampering")["refused"], 4)

    def test_persisted_profile_pin_is_stable_and_tamper_evident(self):
        self.assertEqual(self.run_worker("profile-pin")["pin_refusals"], 2)

    def test_disabled_profile_client_and_callback_drift_fail_closed(self):
        self.assertEqual(self.run_worker("cold-drift")["cold_drift_refusals"], 3)

    def test_exact_read_only_gmail_policy_has_signed_oauth2_access_token_binding(self):
        self.assertEqual(self.run_worker("gmail-policy")["gmail_read_routes"], 8)

    def test_unadmitted_gmail_operations_leave_catalog_and_policy_unchanged(self):
        self.assertEqual(self.run_worker("invalid-rules")["mutation_rollbacks"], 3)

    def test_static_revocation_never_deletes_managed_google_account(self):
        self.assertTrue(self.run_worker("static-revoke")["managed_static_delete_refused"])

    def test_lease_join_rejects_wrong_revoked_and_expired_bindings_without_writes(self):
        self.assertEqual(self.run_worker("lease-binding")["lease_refusals"], 6)

    def test_only_documented_email_alias_preserves_exact_granted_scope_set(self):
        self.assertEqual(self.run_worker("scope-normalization"), {"accepted": 4, "rejected": 9})

    def test_refresh_normalization_requires_exact_committed_managed_account(self):
        self.assertEqual(self.run_worker("refresh-association")["refresh_metadata_refusals"], 4)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
