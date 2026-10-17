#!/usr/bin/env python3
"""Additive npm metadata catalog checks; no provider or install acceptance.

Pure checks need no active profile. Connected workers use real SQLite, custody,
signing and audit in root's bounded network-none lane, never a live workspace.
"""
from contextlib import closing
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_operator_catalog_github as github_tests
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
ACTOR = "operator-npm-catalog-test"
TOKEN = "npm_synthetic_catalog_token_123456789"
REPLACEMENT = "npm_synthetic_catalog_replacement_987654321"
PACKAGES = ["@catchplate/fixture", "catchplate-fixture"]
BUNDLE = "npm_metadata_read_v1"


def refused(function, exception):
    try:
        function()
    except exception:
        return
    raise AssertionError("invalid npm catalog operation was admitted")


class Fixture(github_tests.Fixture):
    def credential(self):
        return self.call(self.mutations.create_npm_credential,
            self.inputs.NpmTokenInput(**self.review(), name="npm synthetic token", secret=TOKEN), ACTOR)

    def fields(self, application, credential, packages=None):
        return {**self.review(), "name": "Read package metadata", "application_id": application["id"],
            "credential_id": credential["id"], "operation_bundle": BUNDLE,
            "packages": list(PACKAGES if packages is None else packages)}

    def rule(self, application, credential, packages=None):
        return self.call(self.mutations.create_npm_rule,
            self.inputs.NpmMetadataRuleInput(**self.fields(application, credential, packages)), ACTOR)

    def generic(self, application, credential, path="/catchplate-fixture", methods=None):
        return self.call(self.mutations.create_rule, self.inputs.RuleInput(**self.review(),
            name="Generic registry path", application_id=application["id"], credential_id=credential["id"],
            upstream_url="https://registry.npmjs.org" + path,
            methods=["GET"] if methods is None else methods, response_fields=["name"]), ACTOR)

    def generic_credential(self):
        return self.call(self.mutations.create_credential, self.inputs.CredentialInput(**self.review(),
            name="Unmarked bearer", auth_type="bearer", secret=TOKEN), ACTOR)["credential"]

    def privacy(self, value):
        text = json.dumps(value, sort_keys=True)
        audit = json.dumps(workspace.rows(self.db, "audit_events"))
        sensitive = [TOKEN, REPLACEMENT, *self.tokens,
            *[row["token_sha256"] for row in self.catalog()["applications"]]]
        assert all(item not in text and item not in audit for item in sensitive), "private material disclosed"


def signed_metadata():
    from catchplate import npm_metadata
    f = Fixture()
    policy_before = f.snapshot()[1:]
    credential, application = f.credential()["credential"], f.application()
    assert f.snapshot()[1:] == policy_before, "unassigned credentials/applications granted authority"
    assert credential["auth_type"] == "bearer" and credential["connection_type"] == "npm_token_v1"
    assert credential["provider_id"] == "npm" and credential["credential_generation"] == 1
    core = f.db.get_credential(credential["id"], include_secret=True)
    assert core["secret"] == TOKEN and core["kind"] == "bearer"
    assert core["metadata"]["provider_id"] == "operator-demo"
    assert core["metadata"]["connection_type"] == "npm_token_v1"
    assert TOKEN not in json.dumps(workspace.rows(f.db, "credentials")), "token persisted unencrypted"
    result = f.rule(application, credential)
    rule = result["access_rule"]
    signed = f.signed()
    route = next(item for item in signed["routes"] if item["id"] == rule["route_id"])
    assert rule["packages"] == PACKAGES and rule["operation_bundle"] == BUNDLE
    assert rule["response_mode"] == "npm_metadata_json_v1"
    assert rule["methods"] == ["GET"] and rule["upstream_url"] == "https://registry.npmjs.org/"
    assert "request_body_mode" not in rule and "query_mode" not in rule
    assert route["match"] == {"scheme": "https", "host": "registry.npmjs.org", "port": 443,
        "methods": ["GET"], "paths": ["/{package}"]}
    assert route["credentialRef"] == credential["id"] and route["principals"] == [application["principal_id"]]
    assert route["credentialHeader"] == npm_metadata.REPLACEMENT
    assert route["adapter"]["type"] == npm_metadata.ADAPTER
    cfg = route["adapter"]["config"]
    assert set(cfg) == {"credentialBinding", "packages", "request", "response"}
    assert cfg["packages"] == PACKAGES and cfg["request"] == npm_metadata.request_profile()
    assert cfg["response"] == npm_metadata.response_profile()
    assert route["constraints"] == [npm_metadata.response_envelope(route["id"] + ".envelope")]
    assert cfg["credentialBinding"] == {"credentialType": "static", "provider": "operator-demo",
        "subjects": [core["metadata"]["provider_subject"]], "secretClass": "bearerToken"}
    principal = next(item for item in signed["principals"] if item["id"] == application["principal_id"])
    assert principal["proxyAuthorization"]["basicTransport"] == {"username": application["id"]}
    status = f.call(f.mutations.catalog_status)
    capability = status["capabilities"]["npm"]
    assert capability["destination_allowed"] is True and capability["metadata_only"] is True
    assert capability["operation_bundles"] == [BUNDLE] and capability["max_active_rules_per_application"] == 1
    assert status["capabilities"]["github"]["operation_bundles"] == [github_tests.READ, github_tests.WRITE]
    assert status["capabilities"]["operation_bundles"] == []
    f.privacy(status)
    committed = f.snapshot()
    f.store.initialize()
    assert f.snapshot() == committed, "reinitialize changed retained npm resources"
    return {"metadata_only_signed": True}


def strict_bindings_and_overlap():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    generic = f.generic_credential()
    github = f.call(f.mutations.create_github_credential, f.inputs.GithubTokenInput(**f.review(),
        name="Separate GitHub token", secret=github_tests.TOKEN), ACTOR)["credential"]
    before = f.snapshot()
    refused(lambda: f.rule(application, generic), ValueError)
    refused(lambda: f.rule(application, github), ValueError)
    refused(lambda: f.generic(application, credential), ValueError)
    assert f.snapshot() == before
    stale = f.inputs.NpmMetadataRuleInput(**f.fields(application, credential))
    rule = f.rule(application, credential)["access_rule"]
    before = f.snapshot()
    refused(lambda: f.call(f.mutations.create_npm_rule, stale, ACTOR), f.schema.CatalogConflict)
    refused(lambda: f.rule(application, credential, ["different-package"]), ValueError)
    refused(lambda: f.generic(application, generic), ValueError)
    assert f.snapshot() == before
    # Both insertion orders, with inactive history permitting an explicit new grant.
    other_application = f.application()
    generic_rule = f.generic(other_application, generic)["access_rule"]
    before = f.snapshot()
    refused(lambda: f.rule(other_application, credential), ValueError)
    assert f.snapshot() == before
    f.call(f.mutations.revoke_rule, f.target(generic_rule["id"]), ACTOR)
    f.rule(other_application, credential)
    f.generic(application, generic, "/-/nested")
    f.generic(application, generic, methods=["POST"])
    f.call(f.mutations.revoke_rule, f.target(rule["id"]), ACTOR)
    replacement_rule = f.rule(application, credential, ["different-package"])["access_rule"]
    before = f.snapshot()
    for collection, identifier, changes in (
            ("credentials", credential["id"], {"connection_type": "unknown"}),
            ("credentials", credential["id"], {"connection_type": None}),
            ("access_rules", replacement_rule["id"], {"placeholder": "Bearer other"}),
            ("access_rules", replacement_rule["id"], {"packages": ["*"]}),
            ("access_rules", replacement_rule["id"], {"methods": ["GET", "POST"]}),
            ("access_rules", replacement_rule["id"], {"request_body_mode": "preserve_json_v1"})):
        bad = deepcopy(f.catalog())
        next(row for row in bad[collection] if row["id"] == identifier).update(changes)
        with closing(f.db.connect()) as conn:
            refused(lambda: f.schema.validate_bindings(conn, bad), f.schema.CatalogIntegrityError)
    bad = deepcopy(f.catalog())
    duplicate = deepcopy(next(row for row in bad["access_rules"] if row["id"] == replacement_rule["id"]))
    duplicate.update(id="12345678-1234-4234-8234-123456789abc", ordinal=99,
        route_id="operator.12345678-1234-4234-8234-123456789abc")
    bad["access_rules"].append(duplicate)
    with closing(f.db.connect()) as conn:
        refused(lambda: f.schema.validate_bindings(conn, bad), f.schema.CatalogIntegrityError)
    assert f.snapshot() == before
    f.signed()
    return {"cross_binding_and_symmetric_overlap_refused": True}


def replacement_and_revocation():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    rule = f.rule(application, credential)["access_rule"]
    before = f.snapshot()
    # The low-level writer must reject mismatched and unknown markers too.
    for marker in ("github_token_v1", "unknown", None):
        with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                metadata = json.loads(conn.execute("SELECT metadata FROM credentials WHERE id=?", (credential["id"],)).fetchone()[0])
                if marker is None:
                    metadata.pop("connection_type")
                else:
                    metadata["connection_type"] = marker
                conn.execute("UPDATE credentials SET metadata=? WHERE id=?", (json.dumps(metadata), credential["id"]))
                refused(lambda: f.db.replace_operator_static_credential_secret_if_version(conn, credential["id"],
                    expected_version=1, secret=REPLACEMENT), f.db.MetadataStoreError)
            finally:
                conn.rollback()
        assert f.snapshot() == before
    before_catalog, before_policy = f.catalog(), f.snapshot()[1:]
    result = f.call(f.mutations.replace_credential_key, f.inputs.ReplaceCredentialKeyInput(
        **f.review(), id=credential["id"], expected_credential_generation=1, secret=REPLACEMENT), ACTOR)
    assert result["credential"]["credential_generation"] == 2
    assert result["credential"]["connection_type"] == "npm_token_v1"
    assert f.db.get_credential(credential["id"], include_secret=True)["secret"] == REPLACEMENT
    assert f.snapshot()[1:] == before_policy
    assert f.catalog()["applications"] == before_catalog["applications"]
    assert f.catalog()["access_rules"] == before_catalog["access_rules"]
    before = f.snapshot()
    refused(lambda: f.call(f.mutations.revoke_credential, f.target(credential["id"]), ACTOR), f.schema.CatalogConflict)
    refused(lambda: f.call(f.mutations.replace_credential_key, f.inputs.ReplaceCredentialKeyInput(
        **f.review(), id=credential["id"], expected_credential_generation=2, secret="invalid token"), ACTOR), ValueError)
    assert f.snapshot() == before
    f.call(f.mutations.revoke_rule, f.target(rule["id"]), ACTOR)
    f.call(f.mutations.revoke_credential, f.target(credential["id"]), ACTOR)
    assert f.db.get_credential(credential["id"], include_secret=True) is None
    before = f.snapshot()
    refused(lambda: f.rule(application, credential), f.schema.CatalogConflict)
    assert f.snapshot() == before
    f.privacy(f.call(f.mutations.catalog_status))
    return {"replacement_and_explicit_revocation": True}


def retained_legacy():
    config, db, store, bundles, schema, _ = workspace.legacy_fixture(with_revocation=False)
    before, signed = workspace.snapshot(db), config.POLICY_BUNDLE_PATH.read_bytes()
    workspace.migrate(db, schema)
    assert workspace.snapshot(db) == before and config.POLICY_BUNDLE_PATH.read_bytes() == signed
    old = workspace.catalog(db, schema)
    from catchplate import operator_catalog_inputs as inputs, operator_catalog_mutations as mutations
    with patch.object(store, "loaded_policy_hash", return_value=None):
        result = mutations.create_npm_credential(inputs.NpmTokenInput(**workspace.review(db, store, schema),
            name="Explicit new npm token", secret=TOKEN), ACTOR)
    current = workspace.catalog(db, schema)
    for collection in ("credentials", "applications", "access_rules"):
        assert current[collection][:len(old[collection])] == old[collection]
    assert result["credential"]["connection_type"] == "npm_token_v1"
    assert config.POLICY_BUNDLE_PATH.read_bytes() == signed
    committed = workspace.snapshot(db, catalog=True)
    store.initialize()
    assert workspace.snapshot(db, catalog=True) == committed
    workspace.verify_signed(config, db, store, bundles)
    return {"legacy_rows_and_policy_unchanged": True}


def failures():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    for statement in ("BEFORE INSERT ON audit_events", "BEFORE UPDATE ON operator_demo_policy"):
        before = f.snapshot()
        with closing(f.db.connect()) as conn, conn:
            conn.execute("CREATE TRIGGER npm_abort " + statement + " BEGIN SELECT RAISE(ABORT, 'synthetic npm refusal'); END")
        try:
            refused(lambda: f.rule(application, credential), sqlite3.IntegrityError)
            assert f.snapshot() == before
        finally:
            with closing(f.db.connect()) as conn, conn:
                conn.execute("DROP TRIGGER npm_abort")
    before = f.snapshot()
    with patch.object(f.bundles, "sign_policy_bundle", side_effect=ValueError("synthetic signing refusal")):
        refused(lambda: f.rule(application, credential), ValueError)
    assert f.snapshot() == before
    return {"rollback_stages": 3}


def destination_refused():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    assert f.call(f.mutations.catalog_status)["capabilities"]["npm"]["destination_allowed"] is False
    before = f.snapshot()
    refused(lambda: f.rule(application, credential), ValueError)
    assert f.snapshot() == before
    return {"store_only_no_destination_bypass": True}


OPERATIONS = {"signed": signed_metadata, "strict": strict_bindings_and_overlap,
    "replacement": replacement_and_revocation, "legacy": retained_legacy,
    "failures": failures, "destination": destination_refused}


class PureCatalogNpmTests(unittest.TestCase):
    def fields(self):
        return {"expected_revision": 1, "expected_policy_hash": "sha256:" + "1" * 64,
            "name": "Read package metadata", "application_id": "12345678-1234-4234-8234-123456789abc",
            "credential_id": "22345678-1234-4234-8234-123456789abc", "operation_bundle": BUNDLE,
            "packages": list(PACKAGES)}

    def test_exact_packages_and_no_caller_selected_authority(self):
        from catchplate.operator_catalog_inputs import NpmMetadataRuleInput
        self.assertEqual(NpmMetadataRuleInput(**self.fields()).packages, PACKAGES)
        for packages in ([], ["*"], ["pkg", "pkg"], ["z", "a"], ["@scope/*"], ["UPPER"], ["pkg/path"],
                ["/pkg"], ["%2fpkg"], ["-pkg"], ["@scope/pkg/-/file.tgz"], ["a" * 215], ["p" + str(i) for i in range(65)]):
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                NpmMetadataRuleInput(**{**self.fields(), "packages": packages})
        for key, value in (("operation_bundle", "npm_install_v1"), ("methods", ["POST"]),
                ("placeholder", "Bearer other"), ("upstream_url", "https://other.example/"),
                ("response_fields", ["name"]), ("credential_input", "insert"),
                ("request_body_mode", "preserve_json_v1"), ("expected_revision", True)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                NpmMetadataRuleInput(**{**self.fields(), key: value})

    def test_token_hidden_and_validation_does_not_quote_secret(self):
        from catchplate.operator_catalog_inputs import NpmTokenInput
        fields = {key: self.fields()[key] for key in ("expected_revision", "expected_policy_hash", "name")}
        self.assertNotIn(TOKEN, repr(NpmTokenInput(**fields, secret=TOKEN)))
        for secret in ("", "invalid private token", "line\nbreak", "x" * 8193, "tökén"):
            with self.subTest(length=len(secret)):
                try:
                    NpmTokenInput(**fields, secret=secret)
                except ValueError as error:
                    if secret:
                        self.assertNotIn(secret, str(error))
                else:
                    self.fail("invalid token admitted")

    def test_closed_marker_dispatch_never_upgrades_unmarked_bearer(self):
        from catchplate import operator_catalog_schema as schema
        record = {"auth_type": "bearer", "header_name": "Authorization"}
        self.assertFalse(schema.validate_static_connection(record))
        for marker in ("npm_token_v1", "github_token_v1"):
            self.assertTrue(schema.validate_static_connection({**record, "connection_type": marker}, {"connection_type": marker}))
        for marker in (None, "unknown", "npm", ""):
            with self.assertRaises(schema.CatalogIntegrityError):
                schema.validate_static_connection({**record, "connection_type": marker})
        for marker in ("npm_token_v1", "github_token_v1"):
            with self.assertRaises(schema.CatalogIntegrityError):
                schema.validate_static_connection(record, {"connection_type": marker})
            with self.assertRaises(schema.CatalogIntegrityError):
                schema.validate_static_connection({**record, "connection_type": marker}, {})

    def test_derived_metadata_rule_and_overlap_are_closed(self):
        from catchplate import operator_catalog_npm as npm, npm_metadata
        from catchplate.operator_catalog_inputs import NpmMetadataRuleInput
        from catchplate.operator_catalog_schema import CatalogIntegrityError
        record = npm.record_fields(NpmMetadataRuleInput(**self.fields()))
        record.update(id="rule", route_id="operator.rule", status="active")
        credential = {"id": "credential", "auth_type": "bearer", "header_name": "Authorization",
            "connection_type": npm.CONNECTION, "provider_subject": "subject"}
        route = npm.render_route(record, credential, "principal")
        self.assertEqual(route["adapter"]["config"]["request"], npm_metadata.request_profile())
        self.assertEqual(route["adapter"]["config"]["response"], npm_metadata.response_profile())
        for key, value in (("methods", ["POST"]), ("packages", ["*"]), ("query_mode", "npm"),
                ("request_body_mode", None), ("response_mode", "unfiltered_json"), ("placeholder", "Bearer other")):
            with self.subTest(key=key), self.assertRaises(CatalogIntegrityError):
                npm.validate_shape({**record, key: value})
        with self.assertRaises(CatalogIntegrityError):
            npm.validate_route_coexistence([record, dict(record)])
        generic = {"status": "active", "application_id": record["application_id"],
            "methods": ["GET"], "upstream_url": npm.ORIGIN + "/other"}
        for values in ([record, generic], [generic, record]):
            with self.assertRaises(CatalogIntegrityError):
                npm.validate_route_coexistence(values)
        for changes in ({"status": "revoked"}, {"methods": ["POST"]}, {"upstream_url": npm.ORIGIN + "/-/nested"},
                {"application_id": "other"}, {"upstream_url": "https://other.example/one"}):
            npm.validate_route_coexistence([record, {**generic, **changes}])


class ConnectedCatalogNpmTests(unittest.TestCase):
    def setUp(self):
        workspace.common.OperatorDemoPersistenceTests.setUp(self)
        self.environment["CATCHPLATE_OPERATOR_DEMO_UPSTREAMS"] = '["https://api.example.com","https://api.github.com","https://registry.npmjs.org"]'

    def run_worker(self, name):
        environment = dict(self.environment)
        if name == "destination":
            environment["CATCHPLATE_OPERATOR_DEMO_UPSTREAMS"] = '["https://api.example.com"]'
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90)
        if result.returncode != 0:
            self.fail("isolated npm catalog worker failed (exit " + str(result.returncode)
                + "): " + github_tests.worker_failure_summary(result))
        return json.loads(result.stdout)

    def test_real_custody_basic_principal_and_signed_metadata_profile(self):
        self.assertTrue(self.run_worker("signed")["metadata_only_signed"])

    def test_cross_bindings_symmetric_overlap_and_explicit_replacement_rule(self):
        self.assertTrue(self.run_worker("strict")["cross_binding_and_symmetric_overlap_refused"])

    def test_retained_generic_rows_and_signed_policy_are_unchanged(self):
        self.assertTrue(self.run_worker("legacy")["legacy_rows_and_policy_unchanged"])

    def test_key_replacement_and_revocation_use_existing_custody(self):
        self.assertTrue(self.run_worker("replacement")["replacement_and_explicit_revocation"])

    def test_audit_policy_and_signing_failures_roll_back(self):
        self.assertEqual(self.run_worker("failures")["rollback_stages"], 3)

    def test_storing_token_does_not_bypass_deployment_destination(self):
        self.assertTrue(self.run_worker("destination")["store_only_no_destination_bypass"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        try:
            outcome = OPERATIONS[sys.argv[2]]()
        except Exception as error:
            print(json.dumps(github_tests.safe_worker_failure(error), sort_keys=True))
            raise SystemExit(1) from None
        print(json.dumps(outcome, sort_keys=True))
    else:
        unittest.main(verbosity=2)
