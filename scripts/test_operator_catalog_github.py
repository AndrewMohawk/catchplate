#!/usr/bin/env python3
"""Real SQLite/encryption/signing tests for explicit GitHub catalog presets.

These cold synthetic workers are not provider or SDK acceptance. Run only in
the root-authorized bounded network-none lane. Gate observation alone is
stubbed; custody, publication, admission, revisions and audit remain real.
"""
from contextlib import closing
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
ACTOR = "operator-github-catalog-test"
TOKEN = "github_pat_synthetic_catalog_token_123456789"
REPLACEMENT = "github_pat_synthetic_catalog_replacement_987654321"
REPOSITORY = {"owner": "serverware-fixture", "name": "operator-demo"}
READ = "github_issues_read_v1"
WRITE = "github_issues_write_v1"


def refused(function, exception):
    try:
        function()
    except exception:
        return
    raise AssertionError("invalid GitHub catalog operation was admitted")


class Fixture:
    def __init__(self):
        (self.config, self.db, self.store, self.bundles, self.schema,
            self.inputs, self.mutations) = workspace.workspace()
        self.tokens = []

    def review(self):
        return workspace.review(self.db, self.store, self.schema)

    def call(self, function, *args):
        with patch.object(self.store, "loaded_policy_hash", return_value=None):
            return function(*args)

    def credential(self):
        return self.call(self.mutations.create_github_credential,
            self.inputs.GithubTokenInput(**self.review(), name="GitHub synthetic token", secret=TOKEN), ACTOR)

    def application(self):
        result = self.call(self.mutations.create_application, self.inputs.ApplicationInput(
            **self.review(), name="GitHub SDK application", token_lifetime_seconds=3600,
            proxy_authentication="basic_and_bearer_v1"), ACTOR)
        self.tokens.append(result["client_token"])
        return result["application"]

    def fields(self, application, credential, bundle=READ):
        return {**self.review(), "name": "GitHub repository permission", "application_id": application["id"],
            "credential_id": credential["id"], "operation_bundle": bundle, "repository": dict(REPOSITORY)}

    def rule(self, application, credential, bundle=READ):
        return self.call(self.mutations.create_github_rule,
            self.inputs.GithubRuleInput(**self.fields(application, credential, bundle)), ACTOR)

    def catalog(self):
        return workspace.catalog(self.db, self.schema)

    def snapshot(self):
        return (workspace.snapshot(self.db, catalog=True), self.config.POLICY_BUNDLE_PATH.read_bytes(),
            self.store.get_policy_high_water())

    def signed(self):
        return workspace.verify_signed(self.config, self.db, self.store, self.bundles)

    def target(self, identifier):
        return self.inputs.TargetInput(**self.review(), id=identifier)

    def privacy(self, value):
        text = json.dumps(value, sort_keys=True)
        audit = json.dumps(workspace.rows(self.db, "audit_events"))
        sensitive = [TOKEN, REPLACEMENT, *self.tokens,
            *[row["token_sha256"] for row in self.catalog()["applications"]]]
        assert all(item not in text and item not in audit for item in sensitive), "private material disclosed"


def signed_presets():
    f = Fixture()
    policy_before = f.snapshot()[1:]
    created = f.credential()
    credential = created["credential"]
    assert f.snapshot()[1:] == policy_before, "token storage changed request authority"
    assert credential["auth_type"] == "bearer" and credential["connection_type"] == "github_token_v1"
    assert credential["provider_id"] == "github" and credential["credential_generation"] == 1
    core = f.db.get_credential(credential["id"], include_secret=True)
    assert core["secret"] == TOKEN and core["kind"] == "bearer"
    assert TOKEN not in json.dumps(workspace.rows(f.db, "credentials")), "token persisted unencrypted"
    app_read, app_write = f.application(), f.application()
    assert f.snapshot()[1:] == policy_before, "unassigned apps granted authority"
    first, second = f.rule(app_read, credential), f.rule(app_write, credential, WRITE)
    signed = f.signed()
    assert len(signed["routes"]) == 2 and len(signed["credentials"]) == 1
    from serverware import github_issues
    for result, app, bundle in ((first, app_read, READ), (second, app_write, WRITE)):
        rule = result["access_rule"]
        route = next(item for item in signed["routes"] if item["id"] == rule["route_id"])
        assert rule["repository"] == REPOSITORY and rule["operation_bundle"] == bundle
        assert rule["response_mode"] == "unfiltered_json_or_empty_v2" and rule["response_fields"] == []
        assert rule["query_mode"] == "githubRestV1" and rule["request_body_mode"] == "preserve_json_v1"
        assert route["match"] == {"scheme": "https", "host": "api.github.com", "port": 443,
            "methods": ["GET"] if bundle == READ else ["GET", "POST"],
            "paths": github_issues.route_paths(REPOSITORY)}
        assert route["credentialRef"] == credential["id"] and route["principals"] == [app["principal_id"]]
        assert route["credentialHeader"] == {"mode": "replaceExact", "expectedValue": "token serverware-github-placeholder-v1"}
        cfg = route["adapter"]["config"]
        assert cfg["githubRepository"] == REPOSITORY and cfg["operationBundle"] == bundle
        assert cfg["request"] == github_issues.request_profile(bundle)
        assert cfg["response"] == github_issues.response_profile()
        assert route["constraints"] == [github_issues.response_envelope(route["id"] + ".envelope")]
        assert result["policy"]["activation"] == "pending"
        principal = next(item for item in signed["principals"] if item["id"] == app["principal_id"])
        assert principal["proxyAuthorization"]["basicTransport"] == {"username": app["id"]}
        assert principal["proxyAuthorization"]["tokenId"] == app["id"]
    status = f.call(f.mutations.catalog_status)
    assert status["capabilities"]["github"]["destination_allowed"] is True
    assert status["capabilities"]["github"]["operation_bundles"] == [READ, WRITE]
    assert status["capabilities"]["operation_bundles"] == [], "legacy Gmail capability was repurposed"
    f.privacy(status)
    committed = f.snapshot()
    f.store.initialize()
    assert f.snapshot() == committed, "reinitialize changed retained GitHub resources"
    return {"signed_presets": 2, "encrypted_and_basic_bound": True}


def legacy_retained():
    config, db, store, bundles, schema, _ = workspace.legacy_fixture(with_revocation=False)
    before, signed = workspace.snapshot(db), config.POLICY_BUNDLE_PATH.read_bytes()
    workspace.migrate(db, schema)
    assert workspace.snapshot(db) == before and config.POLICY_BUNDLE_PATH.read_bytes() == signed
    old = workspace.catalog(db, schema)
    assert all("connection_type" not in row for row in old["credentials"])
    from serverware import operator_catalog_inputs as inputs, operator_catalog_mutations as mutations
    with patch.object(store, "loaded_policy_hash", return_value=None):
        result = mutations.create_github_credential(inputs.GithubTokenInput(**workspace.review(db, store, schema),
            name="Explicit new GitHub token", secret=TOKEN), ACTOR)
    current = workspace.catalog(db, schema)
    for collection in ("credentials", "applications", "access_rules"):
        assert current[collection][:len(old[collection])] == old[collection]
    assert result["credential"]["connection_type"] == "github_token_v1"
    assert config.POLICY_BUNDLE_PATH.read_bytes() == signed
    committed = workspace.snapshot(db, catalog=True)
    store.initialize()
    assert workspace.snapshot(db, catalog=True) == committed and config.POLICY_BUNDLE_PATH.read_bytes() == signed
    workspace.verify_signed(config, db, store, bundles)
    return {"legacy_rows_and_policy_unchanged": True}


def strict_inputs_and_bindings():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    fields = f.fields(application, credential)
    before = f.snapshot()
    cases = [{"repository": value} for value in ({"owner": "a", "name": "b", "id": 1729},
        {"owner": "bad/owner", "name": "b"}, {"owner": "a", "name": ".."},
        {"owner": "a", "name": "%2F"}, {"owner": "a", "name": "b?x"}, None)]
    cases += [{key: value} for key, value in (("operation_bundle", "github_all"), ("methods", ["DELETE"]),
        ("placeholder", "Bearer other"), ("query_mode", "githubRestV1"), ("expected_revision", True),
        ("upstream_url", "https://other.example/"), ("response_fields", ["id"]), ("credential_input", "insert"))]
    for changes in cases:
        refused(lambda changes=changes: f.inputs.GithubRuleInput(**{**fields, **changes}), ValueError)
    for secret in ("", "with space", "line\nbreak", "a.b.c", "-----BEGIN PRIVATE KEY-----", "x" * 8193):
        refused(lambda secret=secret: f.inputs.GithubTokenInput(**f.review(), name="Refused", secret=secret), ValueError)
    assert f.snapshot() == before
    generic = f.call(f.mutations.create_credential, f.inputs.CredentialInput(**f.review(), name="Old generic token",
        auth_type="bearer", secret=TOKEN), ACTOR)["credential"]
    before = f.snapshot()
    refused(lambda: f.rule(application, generic), ValueError)
    refused(lambda: f.call(f.mutations.create_rule, f.inputs.RuleInput(**f.review(), name="No generic bypass",
        application_id=application["id"], credential_id=credential["id"],
        upstream_url="https://api.example.com/v1/items", methods=["GET"], response_fields=["id"]), ACTOR), ValueError)
    assert f.snapshot() == before
    stale = f.inputs.GithubRuleInput(**f.fields(application, credential))
    rule = f.rule(application, credential)["access_rule"]
    before = f.snapshot()
    refused(lambda: f.call(f.mutations.create_github_rule, stale, ACTOR), f.schema.CatalogConflict)
    for collection, identifier, changes in (("credentials", credential["id"], {"connection_type": "unknown"}),
            ("credentials", credential["id"], {"connection_type": None}),
            ("access_rules", rule["id"], {"placeholder": "token different"}),
            ("access_rules", rule["id"], {"methods": ["GET", "DELETE"]}),
            ("access_rules", rule["id"], {"repository": {**REPOSITORY, "id": 1729}})):
        bad = deepcopy(f.catalog())
        next(item for item in bad[collection] if item["id"] == identifier).update(changes)
        with closing(f.db.connect()) as conn:
            refused(lambda: f.schema.validate_bindings(conn, bad), f.schema.CatalogIntegrityError)
    assert f.snapshot() == before
    return {"strict_and_cross_binding_refused": True}


def replacement_marker_refusals(f, credential):
    """Exercise the real writer guard, not only the outer catalog validator."""
    legacy = f.call(f.mutations.create_credential, f.inputs.CredentialInput(**f.review(),
        name="Legacy exact metadata control", auth_type="bearer", secret=TOKEN), ACTOR)["credential"]
    cases = [(credential["id"], target, value) for target, value in (
        ("catalog", "unknown"), ("metadata", "unknown"), ("both", "unknown"),
        ("catalog", None), ("metadata", None), ("extra", "refused"))]
    cases.append((legacy["id"], "extra", "refused"))
    before = f.snapshot()
    for identifier, target, value in cases:
        with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                metadata = json.loads(conn.execute("SELECT metadata FROM credentials WHERE id=?", (identifier,)).fetchone()[0])
                catalog = json.loads(conn.execute("SELECT data_json FROM operator_catalog_credentials WHERE id=?", (identifier,)).fetchone()[0])
                for selected, record in (("metadata", metadata), ("catalog", catalog)):
                    if target in {selected, "both"}:
                        if value is None:
                            record.pop("connection_type")
                        else:
                            record["connection_type"] = value
                if target == "extra":
                    metadata["unexpected"] = value
                conn.execute("UPDATE credentials SET metadata=? WHERE id=?", (json.dumps(metadata), identifier))
                conn.execute("UPDATE operator_catalog_credentials SET data_json=? WHERE id=?", (json.dumps(catalog), identifier))
                core_before = dict(conn.execute("SELECT * FROM credentials WHERE id=?", (identifier,)).fetchone())
                floor_before = dict(conn.execute("SELECT * FROM credential_generations WHERE credential_id=?", (identifier,)).fetchone())
                refused(lambda: f.db.replace_operator_static_credential_secret_if_version(conn, identifier,
                    expected_version=1, secret=REPLACEMENT), f.db.MetadataStoreError)
                assert dict(conn.execute("SELECT * FROM credentials WHERE id=?", (identifier,)).fetchone()) == core_before
                assert dict(conn.execute("SELECT * FROM credential_generations WHERE credential_id=?", (identifier,)).fetchone()) == floor_before
            finally:
                conn.rollback()
        assert f.snapshot() == before, "refused marker altered retained authority"
    return len(cases)


def replacement_and_revocation():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    rule = f.rule(application, credential)["access_rule"]
    assert replacement_marker_refusals(f, credential) == 7
    before_catalog, before_policy = f.catalog(), f.snapshot()[1:]
    result = f.call(f.mutations.replace_credential_key, f.inputs.ReplaceCredentialKeyInput(
        **f.review(), id=credential["id"], expected_credential_generation=1, secret=REPLACEMENT), ACTOR)
    assert result["credential"]["credential_generation"] == 2
    assert result["credential"]["connection_type"] == "github_token_v1"
    assert f.db.get_credential(credential["id"], include_secret=True)["secret"] == REPLACEMENT
    assert f.snapshot()[1:] == before_policy
    assert f.catalog()["applications"] == before_catalog["applications"]
    assert f.catalog()["access_rules"] == before_catalog["access_rules"]
    before = f.snapshot()
    refused(lambda: f.call(f.mutations.revoke_credential, f.target(credential["id"]), ACTOR), f.schema.CatalogConflict)
    refused(lambda: f.call(f.mutations.replace_credential_key, f.inputs.ReplaceCredentialKeyInput(
        **f.review(), id=credential["id"], expected_credential_generation=2, secret="bad token"), ACTOR), ValueError)
    assert f.snapshot() == before
    f.call(f.mutations.revoke_application, f.target(application["id"]), ACTOR)
    assert next(item for item in f.catalog()["access_rules"] if item["id"] == rule["id"])["status"] == "revoked"
    f.call(f.mutations.revoke_credential, f.target(credential["id"]), ACTOR)
    assert f.db.get_credential(credential["id"], include_secret=True) is None
    before = f.snapshot()
    refused(lambda: f.rule(application, credential), f.schema.CatalogConflict)
    assert f.snapshot() == before
    f.privacy(f.call(f.mutations.catalog_status))
    f.signed()
    return {"generation": 2, "assignments_preserved_until_explicit_revoke": True}


def failures_and_pending():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    for statement in ("BEFORE INSERT ON audit_events", "BEFORE UPDATE ON operator_demo_policy"):
        before = f.snapshot()
        with closing(f.db.connect()) as conn, conn:
            conn.execute("CREATE TRIGGER github_abort " + statement + " BEGIN SELECT RAISE(ABORT, 'synthetic GitHub refusal'); END")
        try:
            refused(lambda: f.rule(application, credential), sqlite3.IntegrityError)
            assert f.snapshot() == before, "failed publication changed catalog or authority"
        finally:
            with closing(f.db.connect()) as conn, conn:
                conn.execute("DROP TRIGGER github_abort")
    before = f.snapshot()
    with patch.object(f.bundles, "sign_policy_bundle", side_effect=ValueError("synthetic signing refusal")):
        refused(lambda: f.rule(application, credential), ValueError)
    assert f.snapshot() == before
    replace = os.replace
    def publication_failure(source, destination, *args, **kwargs):
        if Path(destination) == f.config.POLICY_BUNDLE_PATH:
            raise OSError("synthetic postcommit publication refusal")
        return replace(source, destination, *args, **kwargs)
    with patch.object(os, "replace", publication_failure):
        result = f.rule(application, credential)
    assert result["policy"]["activation"] == "pending" and f.snapshot()[1] == before[1]
    committed = workspace.snapshot(f.db, catalog=True)
    f.store.initialize()
    assert workspace.snapshot(f.db, catalog=True) == committed and f.snapshot()[1] != before[1]
    f.signed()
    return {"rollback_stages": 3, "pending_recovered_without_new_mutation": True}


def destination_refused():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    status = f.call(f.mutations.catalog_status)
    assert status["capabilities"]["github"]["destination_allowed"] is False
    before = f.snapshot()
    refused(lambda: f.rule(application, credential), ValueError)
    assert f.snapshot() == before
    return {"store_only_no_destination_bypass": True}


OPERATIONS = {"signed": signed_presets, "legacy": legacy_retained, "strict": strict_inputs_and_bindings,
    "replacement": replacement_and_revocation, "failures": failures_and_pending, "destination": destination_refused}


def safe_worker_failure(error):
    """Keep code locations only: no exception text, source lines or locals."""
    name = type(error).__name__
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name) is None:
        name = "Exception"
    frames, trace = [], error.__traceback__
    while trace is not None:
        code = trace.tb_frame.f_code
        filename, function = Path(code.co_filename).name, code.co_name
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}\.py", filename) is None:
            filename = "external.py"
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}|<module>|<lambda>", function) is None:
            function = "unknown"
        frames.append({"file": filename, "function": function, "line": trace.tb_lineno})
        frames = frames[-16:]
        trace = trace.tb_next
    return {"schema": "serverware.syntheticTestFailure/v1", "exception_type": name, "frames": frames}


def worker_failure_summary(result):
    """Revalidate the closed diagnostic; never fall back to raw child output."""
    try:
        if len(result.stdout) > 8192:
            raise ValueError()
        value = json.loads(result.stdout)
        assert isinstance(value, dict) and set(value) == {"schema", "exception_type", "frames"}
        assert value["schema"] == "serverware.syntheticTestFailure/v1"
        assert isinstance(value["exception_type"], str)
        assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value["exception_type"])
        assert isinstance(value["frames"], list) and len(value["frames"]) <= 16
        for frame in value["frames"]:
            assert isinstance(frame, dict) and set(frame) == {"file", "function", "line"}
            assert isinstance(frame["file"], str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}\.py", frame["file"])
            assert isinstance(frame["function"], str) and re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]{0,127}|<module>|<lambda>", frame["function"])
            assert type(frame["line"]) is int and 1 <= frame["line"] <= 1000000
        return json.dumps(value, sort_keys=True)
    except (AssertionError, KeyError, TypeError, ValueError):
        return "safe diagnostic unavailable; raw child output withheld"


class OperatorCatalogGithubTests(unittest.TestCase):
    def setUp(self):
        workspace.common.OperatorDemoPersistenceTests.setUp(self)
        self.environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = '["https://api.example.com","https://api.github.com"]'

    def run_worker(self, name):
        environment = dict(self.environment)
        if name == "destination":
            environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = '["https://api.example.com"]'
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90)
        if result.returncode != 0:
            self.fail("isolated GitHub catalog worker failed (exit " + str(result.returncode)
                + "): " + worker_failure_summary(result))
        return json.loads(result.stdout)

    def test_real_encrypted_token_basic_principals_and_two_signed_presets(self):
        self.assertEqual(self.run_worker("signed")["signed_presets"], 2)

    def test_retained_legacy_rows_and_signed_bytes_are_not_upgraded(self):
        self.assertTrue(self.run_worker("legacy")["legacy_rows_and_policy_unchanged"])

    def test_strict_dtos_stale_reviews_and_cross_credential_bindings(self):
        self.assertTrue(self.run_worker("strict")["strict_and_cross_binding_refused"])

    def test_key_replacement_preserves_assignments_and_revoke_is_explicit(self):
        self.assertEqual(self.run_worker("replacement")["generation"], 2)

    def test_audit_signing_policy_rollback_and_postcommit_pending(self):
        self.assertEqual(self.run_worker("failures")["rollback_stages"], 3)

    def test_token_store_does_not_bypass_destination_allowlist(self):
        self.assertTrue(self.run_worker("destination")["store_only_no_destination_bypass"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        try:
            outcome = OPERATIONS[sys.argv[2]]()
        except Exception as error:
            print(json.dumps(safe_worker_failure(error), sort_keys=True))
            raise SystemExit(1) from None
        print(json.dumps(outcome, sort_keys=True))
    else:
        unittest.main(verbosity=2)
