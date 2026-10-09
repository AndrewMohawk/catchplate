#!/usr/bin/env python3
"""Cold-profile Google discovery checks; not provider or refresh-health proof.

Each child uses the real operator admission, SQLite catalog and existing API.
Saved-account fixtures use synthetic already-verified metadata and encrypted
tokens, not a completed consent flow. Gate-loaded observation is stubbed and
provider transport is fail-on-contact; no OAuth/profile/catalog guard is patched.
Run in the approved network-none lane.
"""
from contextlib import closing
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_operator_catalog_google as google
import test_operator_google_consent as consent
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]


def expected(profile):
    return {
        "schema": "serverware.operatorGoogleCapability/v1",
        "profile": "operator-google-v1", "provider_id": "google",
        "permission_preset": "gmail_readonly",
        "scopes": ["email", "https://www.googleapis.com/auth/gmail.readonly", "openid"],
        "api_origins": ["https://gmail.googleapis.com"],
        "authorization_origin": "https://accounts.google.com",
        "authorization_path": "/o/oauth2/v2/auth",
        "redirect_uri": profile.redirect_uri,
        "start_path": "/api/operator-demo/oauth/google/start",
        "intents_path": "/api/operator-demo/oauth/google/intents",
    }


def disabled():
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    before = workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    with patch.object(store, "loaded_policy_hash", return_value=None):
        result = mutations.catalog_status()
    caps = result["capabilities"]
    assert caps["oauth"] is False and caps["google_oauth"] is None
    assert caps["credential_types"] == ["bearer", "header"]
    assert (workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()) == before
    return {"disabled": True, "unchanged": True}


def enabled_labels():
    f = google.Fixture()
    before = f.snapshot()
    result = f.call(f.mutations.catalog_status)
    caps = result["capabilities"]
    assert caps["oauth"] is True and caps["google_oauth"] == expected(f.profile)
    assert caps["credential_types"] == ["bearer", "header", "google_oauth"]
    record = result["credentials"][0]
    assert record["provider_account"] == "fixture@example.com"
    assert record["provider_subject"] == f.record["provider_subject"]
    assert record["scopes"] == list(f.profile.scopes)
    assert not any("health" in key or key.startswith("refresh_") for key in record)
    assert not any("health" in key or key.startswith("refresh_") for key in caps["google_oauth"])
    encoded = json.dumps(result, sort_keys=True)
    for private in (google.ACCESS_TOKEN, google.REFRESH_TOKEN, google.CLIENT_SECRET,
            str(os.environ["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE"])):
        assert private not in encoded
    for field in ("oauth_intent_id", "oauth_profile_binding_digest", "secret", "access_token", "refresh_token"):
        assert field not in record
    # Discovery never adds a secret-paste or generic-create fallback.
    google.refused(lambda: f.inputs.CredentialInput(**workspace.review(f.db, f.store, f.schema),
        name="Not a consent flow", auth_type="google_oauth", secret="synthetic-no-fallback"), ValueError)
    assert f.snapshot() == before
    return {"closed_public_capability": True, "no_health_inference": True, "generic_create_refused": True}


def retained_binding():
    f = google.Fixture()
    from serverware import operator_catalog_capabilities as caps
    before = f.snapshot()
    with closing(f.db.connect()) as conn:
        google.refused(lambda: caps.google_oauth(conn), f.schema.CatalogIntegrityError)
        for column, value in (("binding_digest", "sha256:" + "0" * 64), ("binding_json", "{}")):
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE operator_catalog_oauth_profile SET " + column + "=?", (value,))
            google.refused(lambda: caps.google_oauth(conn), f.schema.CatalogIntegrityError)
            conn.rollback()
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM operator_catalog_oauth_profile")
        google.refused(lambda: caps.google_oauth(conn), f.schema.CatalogIntegrityError)
        conn.rollback()
        conn.execute("BEGIN")
        assert caps.google_oauth(conn) == expected(f.profile)
        conn.rollback()
    assert f.snapshot() == before
    return {"retained_binding_refusals": 4, "unchanged": True}


def guarded_http():
    f = consent.Fixture()
    with patch.object(f.store, "loaded_policy_hash", return_value=None), patch.object(
            f.oauth, "request_bytes", side_effect=AssertionError("discovery must not contact a provider")) as provider_request:
        code, raw, headers = f.request("GET", "/api/operator-demo/catalog")
        assert code == 200 and json.loads(raw)["capabilities"]["google_oauth"] == expected(f.profile)
        assert [value for name, value in headers if name.lower() == b"cache-control"] == [b"no-store"]
        # Authentication remains the real route dependency, not a mocked identity.
        code, _, _ = f.request("GET", "/api/operator-demo/catalog", auth=False)
        assert code == 401
        changes = {
            "SERVERWARE_OPERATOR_GOOGLE_PROFILE": "",
            "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": "456-other.apps.googleusercontent.com",
            "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": "https://control.example.com/other",
            "SERVERWARE_NATIVE_ENABLED": "1",
        }
        # Every SERVERWARE_* environment drift invalidates the admitted process
        # in outer middleware, before the catalog's fixed 503 boundary. The
        # direct ASGI fixture propagates that exact guard error; these are not
        # HTTP 503 observations. Retained-binding refusals are tested separately.
        for key, value in changes.items():
            with patch.dict(os.environ, {key: value}):
                try:
                    f.request("GET", "/api/operator-demo/catalog")
                except RuntimeError as exc:
                    assert type(exc) is RuntimeError, key
                    assert str(exc) == "operator demo process configuration changed", key
                else:
                    raise AssertionError(key + " drift did not invalidate operator admission")
        code, raw, _ = f.request("GET", "/api/operator-demo/catalog")
        assert code == 200 and json.loads(raw)["capabilities"]["oauth"] is True
        assert provider_request.call_count == 0, "discovery contacted a provider"
    f.assert_redacted()
    return {"real_auth_required": True, "process_admission_refusals": len(changes), "provider_contacts": 0}


OPERATIONS = {"disabled": disabled, "enabled-labels": enabled_labels,
    "retained-binding": retained_binding, "guarded-http": guarded_http}


class OperatorGoogleCapabilityTests(unittest.TestCase):
    def setUp(self):
        consent.OperatorGoogleConsentTests.setUp(self)

    def worker(self, operation):
        environment = dict(self.environment)
        if operation == "disabled":
            for key in tuple(environment):
                if key == "SERVERWARE_OPERATOR_GOOGLE_PROFILE" or key.startswith("SERVERWARE_GOOGLE_"):
                    del environment[key]
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-35:]))
        return json.loads(result.stdout)

    def test_disabled_profile_preserves_static_only_capability(self):
        self.assertEqual(self.worker("disabled"), {"disabled": True, "unchanged": True})

    def test_enabled_profile_has_closed_redacted_consent_only_discovery(self):
        self.assertTrue(self.worker("enabled-labels")["no_health_inference"])

    def test_retained_binding_is_checked_in_callers_read_snapshot(self):
        self.assertEqual(self.worker("retained-binding")["retained_binding_refusals"], 4)

    def test_real_catalog_auth_and_cold_drift_fail_closed_without_provider_calls(self):
        self.assertEqual(self.worker("guarded-http"), {"real_auth_required": True,
            "process_admission_refusals": 4, "provider_contacts": 0})


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
