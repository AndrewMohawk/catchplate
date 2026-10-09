#!/usr/bin/env python3
"""Explicit first-Google setup with retained SQLite authority and cold restarts.

All catalog/ASGI, encryption, signing, profile and startup guards are real.
Provider transport is a fail-on-contact sentinel, never a successful stub.
Each child uses a fresh process; changing environment in an admitted process
does not stand in for a restart. Run only in the bounded network-none harness.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import uuid

import test_operator_google_consent as consent_tests
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
PATH = "/api/operator-demo/oauth/google/setup"
CLIENT = "123-fixture.apps.googleusercontent.com"
OLD_ORIGINS = ["https://api.example.com", "https://demo-upstream:8443"]
TARGET_ORIGINS = [*OLD_ORIGINS, "https://gmail.googleapis.com"]
CIDRS = ["127.0.0.1/32"]
RETAINED_TABLES = ("credentials", "credential_generations", "operator_demo_connections",
    "operator_demo_revocations", "operator_demo_nonces", "operator_catalog_credentials",
    "operator_catalog_applications", "operator_catalog_rules", "operator_demo_policy")


def file_evidence(directory):
    result = {}
    for relative in ("master.key", "policy-bundle.json", "policy-signing-ed25519.pem",
            "policy-signing-ed25519.pub.pem", "mitmproxy/mitmproxy-ca.pem", "mitmproxy/mitmproxy-ca-cert.pem"):
        path = directory / relative
        if path.exists():
            info = path.stat()
            result[relative] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode & 0o777}
    return result


def readonly_snapshot():
    directory = Path(os.environ["SERVERWARE_DATA_DIR"])
    with closing(sqlite3.connect((directory / "serverware.sqlite3").as_uri() + "?mode=ro", uri=True)) as conn:
        return tuple(conn.iterdump()), file_evidence(directory)


def cold_startup(contacts):
    from serverware import operator_demo
    operator_demo.activate()
    from serverware import oauth
    from serverware.control_plane_startup import validate_control_plane_startup

    def forbidden(request, **_options):
        contacts.append(request.full_url)
        raise AssertionError("metadata-only startup contacted a provider")

    # Actual production configuration/preflight/db/bootstrap order; no HTTP
    # server, worker loop, or replacement profile/schema/startup guards.
    with patch.object(oauth, "request_bytes", side_effect=forbidden):
        validate_control_plane_startup()


class Fixture(consent_tests.Fixture):
    def __init__(self):
        self.provider_calls = []
        cold_startup(self.provider_calls)
        from serverware import config, db, operator_demo_store, policy_bundle
        from serverware import operator_catalog_schema, operator_catalog_inputs, operator_catalog_mutations
        self.config, self.db, self.store, self.bundles = config, db, operator_demo_store, policy_bundle
        self.schema, self.inputs, self.mutations = operator_catalog_schema, operator_catalog_inputs, operator_catalog_mutations
        from serverware import app, auth, oauth, operator_demo, operator_google_setup, operator_catalog_oauth_profile
        self.app, self.auth, self.oauth = app, auth, oauth
        self.demo, self.setup, self.profiles = operator_demo, operator_google_setup, operator_catalog_oauth_profile
        self.cookie = None

    def rows(self, table):
        if table == "operator_google_setups":
            with closing(self.db.connect()) as conn:
                return [dict(row) for row in conn.execute("SELECT * FROM operator_google_setups ORDER BY operation_id")]
        return super().rows(table)

    def provider(self, request, **_options):
        self.provider_calls.append(request.full_url)
        raise AssertionError("metadata-only setup contacted a provider")

    def snapshot(self):
        with closing(self.db.connect()) as conn:
            return tuple(conn.iterdump()), file_evidence(self.config.DATA_DIR)

    def authority(self):
        with closing(self.db.connect()) as conn:
            rows = {table: [dict(row) for row in conn.execute("SELECT * FROM " + table + " ORDER BY rowid")]
                for table in RETAINED_TABLES}
        return {"rows": rows, "files": file_evidence(self.config.DATA_DIR)}

    def seed(self):
        credential = workspace.create_credential(self.db, self.store, self.schema, self.inputs, self.mutations)["credential"]
        first = workspace.create_application(self.db, self.store, self.schema, self.inputs, self.mutations)
        active = workspace.create_rule(self.db, self.store, self.schema, self.inputs, self.mutations,
            first["application"]["id"], credential["id"])["access_rule"]
        second = workspace.create_application(self.db, self.store, self.schema, self.inputs, self.mutations)
        historical = workspace.create_rule(self.db, self.store, self.schema, self.inputs, self.mutations,
            second["application"]["id"], credential["id"])["access_rule"]
        self.mutations.revoke_application(self.inputs.TargetInput(**self.review(), id=second["application"]["id"]),
            workspace.common._ACTOR)
        from serverware.ca_material import ensure_mitm_ca_material
        key, cert = ensure_mitm_ca_material()
        assert key.is_file() and cert.is_file()
        assert self.db.get_credential(credential["id"], include_secret=True)["secret"] == workspace.common._PROVIDER_SECRET
        saved = workspace.catalog(self.db, self.schema)
        assert next(row for row in saved["applications"] if row["id"] == first["application"]["id"])["token_sha256"] == (
            "sha256:" + hashlib.sha256(first["client_token"].encode()).hexdigest())
        assert next(row for row in saved["access_rules"] if row["id"] == historical["id"])["status"] == "revoked"
        assert next(row for row in saved["access_rules"] if row["id"] == active["id"])["status"] == "active"
        self.db.reserve_credential_lease_nonce(workspace.common._NONCE_KEY, workspace.common._NONCE,
            now_epoch_ms=int(time.time() * 1000))
        assert len(self.rows("operator_demo_nonces")) == 1
        workspace.verify_signed(self.config, self.db, self.store, self.bundles)
        return credential

    def call(self, method, path=PATH, *, body=None, expected=200, **options):
        code, raw, headers = self.request(method, path, body=body, **options)
        assert code == expected, (code, expected)
        assert [value for name, value in headers if name.lower() == b"cache-control"] == [b"no-store"]
        assert workspace.common._PROVIDER_SECRET.encode() not in raw
        assert consent_tests.google_tests.CLIENT_SECRET.encode() not in raw
        return json.loads(raw)

    def setup_review(self):
        result = self.call("GET")
        assert result["schema"] == "serverware.operatorGoogleSetupReview/v1"
        return result

    def payload(self):
        review = self.setup_review()
        assert review["eligible"] is True
        return {key: review[key] for key in ("expected_revision", "expected_policy_hash", "expected_settings_digest")} | {
            "operation_id": str(uuid.uuid4()), "client_id": CLIENT}

    def public(self, identifier):
        result = self.call("GET", PATH + "/" + identifier)
        assert result["schema"] == "serverware.operatorGoogleSetup/v1"
        return result

    def disabled(self):
        assert self.profiles.selected() is False
        with closing(self.db.connect()) as conn:
            assert conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_catalog_oauth_profile'").fetchone() is None
            from serverware import operator_catalog_capabilities
            conn.execute("BEGIN")
            assert operator_catalog_capabilities.google_oauth(conn) is None
        assert not self.provider_calls

    def prepare(self):
        before = self.authority()
        settings = self.rows("operator_demo_settings")
        payload = self.payload()
        result = self.call("POST", body=payload, expected=201)
        assert result["operation_id"] == payload["operation_id"] and result["status"] == "pending"
        assert result["reviewed_revision"] == payload["expected_revision"]
        assert result["staged_revision"] == result["revision"] == payload["expected_revision"] + 1
        assert result["activation_receipt"] is None and result["policy_hash"] == payload["expected_policy_hash"]
        assert self.public(payload["operation_id"]) == result
        assert self.authority() == before and self.rows("operator_demo_settings") == settings
        assert workspace.catalog(self.db, self.schema)["revision"] == result["staged_revision"]
        self.disabled()
        return result


def prepare(*, activation_failure=False):
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        f.seed()
        operation = f.prepare()
        assert operation["old_settings"] == {"allowed_upstreams": OLD_ORIGINS, "fixture_cidrs": CIDRS}
        assert operation["target_settings"] == {"allowed_upstreams": TARGET_ORIGINS, "fixture_cidrs": CIDRS}
        before = f.snapshot()
        # Persisted intent is not an in-process capability upgrade.
        f.call("POST", "/api/operator-demo/oauth/google/start", body={**f.review(),
            "name": "Setup does not enable consent", "permission_preset": "gmail_readonly"}, expected=403)
        assert f.snapshot() == before and not f.provider_calls
        if activation_failure:
            with closing(f.db.connect()) as conn, conn:
                conn.execute("CREATE TRIGGER google_setup_activation_abort BEFORE INSERT ON audit_events "
                    "WHEN NEW.event_type='operator_catalog.google_setup.activated' "
                    "BEGIN SELECT RAISE(ABORT,'synthetic activation audit refusal'); END")
    return {"operation": operation, "authority": f.authority(), "audit": f.rows("audit_events")}


def activate(identifier):
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        profile = f.profiles.require_profile()
        assert profile.client_id == CLIENT and list(profile.api_origins) == ["https://gmail.googleapis.com"]
        assert f.demo.settings()["allowed_upstreams"] == TARGET_ORIGINS
        assert f.demo.settings()["fixture_cidrs"] == CIDRS
        with closing(f.db.connect()) as conn:
            from serverware import operator_catalog_capabilities
            conn.execute("BEGIN")
            assert operator_catalog_capabilities.google_oauth(conn)["profile"] == "operator-google-v1"
        workspace.verify_signed(f.config, f.db, f.store, f.bundles)
        operation = f.public(identifier)
        assert operation["status"] == "activated"
        receipt = operation["activation_receipt"]
        assert receipt["operation_id"] == identifier and receipt["activated_revision"] == operation["revision"]
        assert receipt["policy_hash"] == operation["policy_hash"]
        assert receipt["profile_binding_digest"] == profile.binding_digest == operation["profile_binding_digest"]
        assert operation["revision"] == operation["staged_revision"] + 1
        assert not f.provider_calls
    return {"authority": f.authority(), "audit": f.rows("audit_events"),
        "operation": operation, "revision": workspace.catalog(f.db, f.schema)["revision"],
        "settings": f.rows("operator_demo_settings")}


def refused_restart():
    before, contacts = readonly_snapshot(), []
    try:
        cold_startup(contacts)
    except RuntimeError:
        pass
    else:
        raise AssertionError("unreviewed first Google startup was admitted")
    assert contacts == [], "refused startup contacted a provider"
    assert readonly_snapshot() == before, "refused preflight changed retained SQLite/key/CA/policy state"
    return {"refused_without_transition_writes": True, "provider_contacts": 0}


def activation_rollback():
    from serverware import operator_demo
    original_bootstrap = operator_demo.bootstrap
    before, contacts = [], []

    def observed_bootstrap():
        # Core initialization legitimately refreshes a migration timestamp.
        # Observe the actual activation boundary, then call the real bootstrap.
        before.append(readonly_snapshot())
        return original_bootstrap()

    with patch.object(operator_demo, "bootstrap", side_effect=observed_bootstrap):
        try:
            cold_startup(contacts)
        except sqlite3.IntegrityError as error:
            assert str(error) == "synthetic activation audit refusal"
        else:
            raise AssertionError("activation ignored the real audit failure")
    assert len(before) == 1, "activation boundary was not observed exactly once"
    assert contacts == []
    assert readonly_snapshot() == before[0], "failed activation retained partial profile/settings/owner state"
    return {"activation_audit_failure_full_rollback": True, "provider_contacts": 0}


def advance_revision():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        previous = f.review()
        workspace.create_credential(f.db, f.store, f.schema, f.inputs, f.mutations, "Intervening static credential")
        current = f.review()
        assert current["expected_revision"] == previous["expected_revision"] + 1
        assert current["expected_policy_hash"] == previous["expected_policy_hash"]
        assert f.rows("operator_google_setups")[0]["status"] == "pending"
        f.disabled()
    return {"revision_advanced_with_same_policy": True}


def retained_without_prepare():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        f.seed()
        review = f.setup_review()
        assert review["old_settings"] == review["target_settings"]
        assert review["old_settings"]["allowed_upstreams"] == TARGET_ORIGINS
        f.disabled()
    return {"gmail_already_allowed": True, "authority": f.authority()}


def fresh_google():
    f = Fixture()
    profile = f.profiles.require_profile()
    assert profile.client_id == CLIENT
    with closing(f.db.connect()) as conn:
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_google_setups'").fetchone() is None
    assert workspace.catalog(f.db, f.schema)["credentials"] == []
    workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    assert not f.provider_calls
    return {"fresh_profile_without_setup": True}


def legacy_seed():
    # Existing historical fixture suppresses only catalog creation during its
    # original bootstrap. The subsequent cold preflight is fully unmodified.
    config, db, _store, _bundles, schema, _tokens = workspace.legacy_fixture(with_revocation=False)
    assert not schema.active()
    with closing(db.connect()) as conn:
        assert conn.execute("SELECT COUNT(*) FROM operator_demo_connections").fetchone()[0] == 2
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_catalog_state'").fetchone() is None
    return {"retained_legacy_without_catalog": True}


def helper_checks(name):
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        f.seed()
        if name == "lifecycle_checks":
            from operator_google_setup_lifecycle_checks import run_lifecycle_checks as action
        elif name == "api_checks":
            from operator_google_setup_api_checks import run_api_checks as action
        else:
            assert name == "transaction_checks"
            from operator_google_setup_api_checks import run_transaction_checks as action
        result = action(f)
        assert f.provider_calls == [], "setup helper contacted a provider"
        return result


class OperatorGoogleSetupTests(unittest.TestCase):
    def setUp(self):
        consent_tests.OperatorGoogleConsentTests.setUp(self)
        self.google_environment = dict(self.environment)
        self.environment = {key: value for key, value in self.environment.items()
            if key != "SERVERWARE_OPERATOR_GOOGLE_PROFILE" and not key.startswith("SERVERWARE_GOOGLE_")}
        self.environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = json.dumps(OLD_ORIGINS)
        self.environment["SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS"] = json.dumps(CIDRS)
        self.google_environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = json.dumps(TARGET_ORIGINS)
        self.google_environment["SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS"] = json.dumps(CIDRS)

    def worker(self, operation, *, google=False, changes=None, identifier=None):
        environment = dict(self.google_environment if google else self.environment)
        environment.update(changes or {})
        command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation]
        if identifier is not None:
            command.append(identifier)
        result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        return json.loads(result.stdout)

    def test_prepare_restart_preserves_saved_authority(self):
        prepared = self.worker("prepare")
        operation = prepared["operation"]
        activated = self.worker("activate", google=True, identifier=operation["operation_id"])
        self.assertEqual(activated["authority"], prepared["authority"])
        self.assertEqual(activated["audit"][:len(prepared["audit"])], prepared["audit"])
        self.assertEqual(activated["revision"], operation["staged_revision"] + 1)
        self.assertEqual(activated["operation"]["policy_hash"], operation["policy_hash"])
        events = [row for row in activated["audit"] if row["event_type"] == "operator_catalog.google_setup.activated"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["id"], "operator-google-setup:" + operation["operation_id"] + ":activated")
        self.assertEqual(json.loads(activated["settings"][0]["settings_json"]), operation["target_settings"])
        reopened = self.worker("activate", google=True, identifier=operation["operation_id"])
        self.assertEqual(reopened, activated)

    def test_prepare_http_and_cas_refusals(self):
        self.worker("api_checks")

    def test_restart_binding_and_stale_revision_refusals(self):
        self.worker("prepare_rollback")
        for changes in (
                {"SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": "456-other.apps.googleusercontent.com"},
                {"SERVERWARE_OPERATOR_DEMO_UPSTREAMS": json.dumps(TARGET_ORIGINS[1:])},
                {"SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS": '["127.0.0.2/32"]'}):
            self.worker("refused_restart", google=True, changes=changes)
        self.worker("activation_rollback", google=True)
        self.worker("advance_revision")
        self.worker("refused_restart", google=True)

    def test_retained_gmail_origin_requires_prepare_but_fresh_profile_works(self):
        self.worker("retained_without_prepare", changes={"SERVERWARE_OPERATOR_DEMO_UPSTREAMS": json.dumps(TARGET_ORIGINS)})
        self.worker("refused_restart", google=True)
        self.worker("fresh_google", google=True, changes={"SERVERWARE_DATA_DIR": str(Path(self.scratch.name) / "fresh-google")})
        legacy_path = str(Path(self.scratch.name) / "legacy")
        self.worker("legacy_seed", changes={"SERVERWARE_DATA_DIR": legacy_path,
            "SERVERWARE_OPERATOR_DEMO_UPSTREAMS": json.dumps(TARGET_ORIGINS)})
        self.worker("refused_restart", google=True, changes={"SERVERWARE_DATA_DIR": legacy_path})

    def test_cancel_and_new_preparation_preserve_one_shot_ids(self):
        self.worker("lifecycle_checks")

    def test_audit_rollback_and_lost_commit_acknowledgement(self):
        self.worker("transaction_checks")


if __name__ == "__main__":
    if len(sys.argv) in (3, 4) and sys.argv[1] == "--worker":
        os.umask(0o077)
        name = sys.argv[2]
        if name == "activate":
            assert len(sys.argv) == 4
            result = activate(sys.argv[3])
        elif name in {"api_checks", "lifecycle_checks", "transaction_checks"}:
            result = helper_checks(name)
        elif name == "prepare_rollback":
            result = prepare(activation_failure=True)
        else:
            result = {"prepare": prepare, "refused_restart": refused_restart,
                "advance_revision": advance_revision, "retained_without_prepare": retained_without_prepare,
                "activation_rollback": activation_rollback,
                "fresh_google": fresh_google, "legacy_seed": legacy_seed}[name]()
        print(json.dumps(result, sort_keys=True))
    else:
        unittest.main(verbosity=2)
