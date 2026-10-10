#!/usr/bin/env python3
"""Npm publish catalog tests; isolated custody/policy, not provider acceptance.

Connected workers require root's disposable network-none backend lane. Only
gate observation is synthetic; publication, SQLite, encryption and audit are real.
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
import test_operator_catalog_npm as metadata_tests
import test_operator_catalog_activity as activity_tests
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
ACTOR = "operator-npm-publish-catalog-test"
PACKAGE = "@serverware/fixture"
BUNDLE = "npm_publish_v1"
WINDOW = {"start": "09:00", "end": "17:00"}


class Fixture(metadata_tests.Fixture):
    def fields(self, application, credential, *, package=PACKAGE, tag="latest", window=None):
        return {**self.review(), "name": "Publish selected package", "application_id": application["id"],
            "credential_id": credential["id"], "operation_bundle": BUNDLE, "package": package,
            "tag": tag, "publishing_window": window}

    def rule(self, application, credential, **options):
        return self.call(self.mutations.create_npm_publish_rule,
            self.inputs.NpmPublishRuleInput(**self.fields(application, credential, **options)), ACTOR)

    def metadata_rule(self, application, credential):
        return self.call(self.mutations.create_npm_rule, self.inputs.NpmMetadataRuleInput(
            **self.review(), name="Metadata only", application_id=application["id"],
            credential_id=credential["id"], operation_bundle=metadata_tests.BUNDLE,
            packages=[PACKAGE]), ACTOR)


def refused(function, exception=ValueError):
    metadata_tests.refused(function, exception)


def route_pair(f, rule):
    routes = {item["id"]: item for item in f.signed()["routes"]}
    return routes[rule["route_id"]], routes[rule["route_id"] + ".metadata"]


def signed_publish():
    from serverware import npm_metadata, npm_publish
    f = Fixture()
    before_policy = f.snapshot()[1:]
    credential, application = f.credential()["credential"], f.application()
    assert f.snapshot()[1:] == before_policy
    result = f.rule(application, credential, tag="beta", window=WINDOW)
    rule = result["access_rule"]
    assert rule["methods"] == ["PUT"] and rule["package"] == PACKAGE and rule["tag"] == "beta"
    assert rule["publishing_window"] == WINDOW and rule["response_mode"] == "npm_publish_json_v1"
    assert "request_body_mode" not in rule and "query_mode" not in rule and "packages" not in rule
    primary, companion = route_pair(f, rule)
    for route, method in ((primary, "PUT"), (companion, "GET")):
        assert route["match"] == {"scheme": "https", "host": "registry.npmjs.org", "port": 443,
            "methods": [method], "paths": ["/{package}"]}
        assert route["credentialRef"] == credential["id"]
        assert route["principals"] == [application["principal_id"]]
        assert route["credentialHeader"] == npm_metadata.REPLACEMENT
        assert "jit" not in route
    config = primary["adapter"]["config"]
    assert primary["adapter"]["type"] == "npm.publish.v1"
    assert set(config) == {"credentialBinding", "package", "tag", "request", "response"}
    assert config["package"] == PACKAGE and config["tag"] == "beta"
    assert config["request"] == npm_publish.request_profile() and config["response"] == npm_publish.response_profile()
    assert primary["constraints"] == [npm_publish.response_envelope(primary["id"] + ".envelope"),
        {"id": primary["id"] + ".publishing-window", "type": "requestTimeWindow", "phase": "request",
            "timezone": "UTC", "dailyWindows": [WINDOW]}]
    assert companion["adapter"]["type"] == "npm.metadata.v1"
    assert companion["adapter"]["config"]["packages"] == [PACKAGE]
    assert companion["adapter"]["config"]["credentialBinding"] == config["credentialBinding"]
    assert companion["constraints"] == [npm_metadata.response_envelope(companion["id"] + ".envelope")]
    other = f.application()
    unrestricted = f.rule(other, credential, package="serverware-fixture")["access_rule"]
    assert unrestricted["tag"] == "latest" and unrestricted["publishing_window"] is None
    assert len(route_pair(f, unrestricted)[0]["constraints"]) == 1
    status = f.call(f.mutations.catalog_status)
    capability = status["capabilities"]["npm_publish"]
    assert capability["destination_allowed"] and capability["read_metadata_included"]
    assert capability["max_request_body_bytes"] == 16777216 and capability["max_tarball_bytes"] == 8388608
    assert capability["publishing_window_timezone"] == "UTC" and capability["default_tag"] == "latest"
    assert next(item for item in status["applications"] if item["id"] == application["id"])["active_rule_count"] == 1
    assert status["credentials"][0]["active_rule_count"] == 2
    assert any(row["event_type"] == "operator_catalog.access_rule.npm_publish_created"
        for row in workspace.rows(f.db, "audit_events"))
    f.privacy(status)
    committed = f.snapshot()
    f.store.initialize()
    assert f.snapshot() == committed, "restart changed the two-route permission"
    return {"two_routes_one_permission": True}


def overlap():
    f = Fixture()
    credential, generic = f.credential()["credential"], f.generic_credential()
    app = f.application()
    publish = f.rule(app, credential)["access_rule"]
    for action in (lambda: f.rule(app, credential, package="other"), lambda: f.metadata_rule(app, credential),
            lambda: f.generic(app, generic), lambda: f.generic(app, generic, methods=["PUT"])):
        before = f.snapshot()
        refused(action)
        assert f.snapshot() == before
    for method in ("GET", "PUT"):
        other = f.application()
        old = f.generic(other, generic, methods=[method])["access_rule"]
        before = f.snapshot()
        refused(lambda: f.rule(other, credential))
        assert f.snapshot() == before
        f.call(f.mutations.revoke_rule, f.target(old["id"]), ACTOR)
        f.rule(other, credential)
    metadata_app = f.application()
    old_metadata = f.metadata_rule(metadata_app, credential)["access_rule"]
    before = f.snapshot()
    refused(lambda: f.rule(metadata_app, credential))
    assert f.snapshot() == before
    # Existing metadata-only grants do not acquire a new PUT prohibition.
    f.generic(metadata_app, generic, methods=["PUT"])
    f.generic(app, generic, "/-/nested", methods=["GET", "PUT"])
    f.generic(app, generic, methods=["POST"])
    f.call(f.mutations.revoke_rule, f.target(publish["id"]), ACTOR)
    f.metadata_rule(app, credential)
    assert old_metadata["operation_bundle"] == metadata_tests.BUNDLE
    return {"symmetric_overlap_without_legacy_broadening": True}


def credential_and_retained_bindings():
    f = Fixture()
    credential, generic, application = f.credential()["credential"], f.generic_credential(), f.application()
    github = f.call(f.mutations.create_github_credential, f.inputs.GithubTokenInput(**f.review(),
        name="Separate provider", secret=github_tests.TOKEN), ACTOR)["credential"]
    before = f.snapshot()
    refused(lambda: f.rule(application, generic))
    refused(lambda: f.rule(application, github))
    assert f.snapshot() == before
    stale = f.inputs.NpmPublishRuleInput(**f.fields(application, credential))
    rule = f.rule(application, credential)["access_rule"]
    before = f.snapshot()
    refused(lambda: f.call(f.mutations.create_npm_publish_rule, stale, ACTOR), f.schema.CatalogConflict)
    changes = ({"package": "*"}, {"tag": "1.2.3"}, {"publishing_window": {**WINDOW, "timezone": "UTC"}},
        {"publishing_window": {"start": "17:00", "end": "09:00"}}, {"methods": ["GET", "PUT"]},
        {"placeholder": "Bearer different"}, {"response_mode": "unfiltered_json"},
        {"request_body_mode": "preserve_json_v1"}, {"packages": [PACKAGE]}, {"companion_route_id": "arbitrary"})
    for change in changes:
        bad = deepcopy(f.catalog())
        next(item for item in bad["access_rules"] if item["id"] == rule["id"]).update(change)
        with closing(f.db.connect()) as conn:
            refused(lambda: f.schema.validate_bindings(conn, bad), f.schema.CatalogIntegrityError)
    assert f.snapshot() == before
    return {"strict_binding_and_stale_cas": True}


def replace_revoke():
    f = Fixture()
    credential = f.credential()["credential"]
    one, two = f.application(), f.application()
    first, second = f.rule(one, credential)["access_rule"], f.rule(two, credential)["access_rule"]
    before_policy, before_rules = f.snapshot()[1:], f.catalog()["access_rules"]
    result = f.call(f.mutations.replace_credential_key, f.inputs.ReplaceCredentialKeyInput(**f.review(),
        id=credential["id"], expected_credential_generation=1, secret=metadata_tests.REPLACEMENT), ACTOR)
    assert result["credential"]["credential_generation"] == 2
    assert f.snapshot()[1:] == before_policy and f.catalog()["access_rules"] == before_rules
    rotated = f.call(f.mutations.rotate_application_token, f.inputs.RotateApplicationInput(**f.review(),
        id=one["id"], token_lifetime_seconds=3600), ACTOR)
    f.tokens.append(rotated["client_token"])
    assert len(f.signed()["routes"]) == 4
    primary, companion = route_pair(f, first)
    assert primary["principals"] == companion["principals"] == [one["principal_id"]]
    before = f.snapshot()
    refused(lambda: f.call(f.mutations.revoke_credential, f.target(credential["id"]), ACTOR), f.schema.CatalogConflict)
    assert f.snapshot() == before
    f.call(f.mutations.revoke_rule, f.target(first["id"]), ACTOR)
    remaining = {item["id"] for item in f.signed()["routes"]}
    assert remaining == {second["route_id"], second["route_id"] + ".metadata"}
    result = f.call(f.mutations.revoke_application, f.target(two["id"]), ACTOR)
    assert result["affected_rule_ids"] == [second["id"]]
    assert not any(item["id"] in remaining for item in f.signed()["routes"])
    f.call(f.mutations.revoke_credential, f.target(credential["id"]), ACTOR)
    assert f.db.get_credential(credential["id"], include_secret=True) is None
    f.privacy(f.call(f.mutations.catalog_status))
    return {"both_routes_revoked_together": True}


def retained_metadata():
    f = Fixture()
    credential, one = f.credential()["credential"], f.application()
    old = f.metadata_rule(one, credential)["access_rule"]
    old_catalog = f.catalog()
    old_route = deepcopy(next(item for item in f.signed()["routes"] if item["id"] == old["route_id"]))
    old_capability = f.call(f.mutations.catalog_status)["capabilities"]["npm"]
    f.rule(f.application(), credential)
    assert f.catalog()["access_rules"][0] == old_catalog["access_rules"][0]
    assert next(item for item in f.signed()["routes"] if item["id"] == old["route_id"]) == old_route
    assert f.call(f.mutations.catalog_status)["capabilities"]["npm"] == old_capability
    committed = f.snapshot()
    f.store.initialize()
    assert f.snapshot() == committed
    return {"old_metadata_unchanged": True}


def rollback():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    for statement in ("BEFORE INSERT ON audit_events", "BEFORE UPDATE ON operator_demo_policy"):
        before = f.snapshot()
        with closing(f.db.connect()) as conn, conn:
            conn.execute("CREATE TRIGGER npm_publish_abort " + statement
                + " BEGIN SELECT RAISE(ABORT, 'synthetic npm publication refusal'); END")
        try:
            refused(lambda: f.rule(application, credential), sqlite3.IntegrityError)
            assert f.snapshot() == before
        finally:
            with closing(f.db.connect()) as conn, conn:
                conn.execute("DROP TRIGGER npm_publish_abort")
    before = f.snapshot()
    with patch.object(f.bundles, "sign_policy_bundle", side_effect=ValueError("synthetic signing refusal")):
        refused(lambda: f.rule(application, credential))
    assert f.snapshot() == before
    # File-publication failure after commit remains a retained pending result.
    with patch.object(f.store, "materialize", side_effect=OSError("synthetic publication refusal")):
        result = f.rule(application, credential)
    assert result["policy"]["activation"] == "pending"
    assert f.catalog()["access_rules"][0]["id"] == result["access_rule"]["id"]
    f.store.materialize()
    assert len(f.signed()["routes"]) == 2
    return {"rollback_and_postcommit_distinguished": True}


def activity_alias():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    rule = f.rule(application, credential)["access_rule"]

    def record(attempt, route, method):
        start, terminal = activity_tests.response(attempt=attempt, credential=credential["id"],
            principal=application["principal_id"], route=route)
        start["method"] = terminal["method"] = method
        start["credential_version"] = terminal["credential_version"] = 1
        with closing(f.db.connect()) as conn, conn:
            f.db.append_audit_event(conn, event_type=activity_tests.START,
                actor_type="data-plane", actor_id="synthetic-gate", event=start)
            last = f.db.append_audit_event(conn, event_type=activity_tests.RELEASE,
                actor_type="data-plane", actor_id="synthetic-gate", event=terminal)
        return last

    record(1, rule["route_id"], "PUT")
    record(2, rule["route_id"] + ".metadata", "GET")
    status = f.call(f.mutations.catalog_status)["observed_activity"]
    observed = status["accounts"][0]["last_successful_response"]
    assert observed is not None and observed["rule_id"] == rule["id"]
    assert status["window"]["unmatched_responses"] == 0
    for attempt, route, method in ((3, rule["route_id"] + ".metadata.extra", "GET"),
            (4, rule["route_id"] + ".metadata", "PUT"), (5, rule["route_id"], "GET")):
        record(attempt, route, method)
    status = f.call(f.mutations.catalog_status)["observed_activity"]
    assert status["accounts"][0]["last_successful_response"] == observed
    assert status["window"]["unmatched_responses"] == 3
    return {"exact_derived_alias_only": True}


def destination():
    f = Fixture()
    credential, application = f.credential()["credential"], f.application()
    assert f.call(f.mutations.catalog_status)["capabilities"]["npm_publish"]["destination_allowed"] is False
    before = f.snapshot()
    refused(lambda: f.rule(application, credential))
    assert f.snapshot() == before
    return {"destination_required": True}


OPERATIONS = {"signed": signed_publish, "overlap": overlap, "bindings": credential_and_retained_bindings,
    "revoke": replace_revoke, "retained": retained_metadata, "rollback": rollback,
    "activity": activity_alias, "destination": destination}


class PureNpmPublishCatalogTests(unittest.TestCase):
    def fields(self):
        return {"expected_revision": 1, "expected_policy_hash": "sha256:" + "1" * 64,
            "name": "Publish selected package", "application_id": activity_tests.APPLICATION,
            "credential_id": activity_tests.CREDENTIAL, "operation_bundle": BUNDLE, "package": PACKAGE}

    def test_exact_public_dto_and_safe_defaults(self):
        from serverware.operator_catalog_inputs import NpmPublishRuleInput
        value = NpmPublishRuleInput(**self.fields())
        self.assertEqual(value.tag, "latest")
        self.assertIsNone(value.publishing_window)
        self.assertEqual(NpmPublishRuleInput(**self.fields(), publishing_window=WINDOW).publishing_window.model_dump(), WINDOW)
        for key, value in (("package", "*"), ("package", "UPPER"), ("package", "@scope/pkg/-/payload.tgz"),
                ("tag", "1.2.3"), ("tag", "Beta"), ("tag", "v" * 65), ("methods", ["PUT"]),
                ("placeholder", "Bearer custom"), ("credential_input", "insert"), ("response_fields", ["ok"]),
                ("expected_revision", True), ("operation_bundle", "npm_install_v1")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                NpmPublishRuleInput(**{**self.fields(), key: value})

    def test_window_is_exact_utc_daytime_no_hidden_weekdays(self):
        from serverware.operator_catalog_inputs import NpmPublishRuleInput
        for window in ({"start": "17:00", "end": "09:00"}, {"start": "09:00", "end": "09:00"},
                {"start": "9:00", "end": "17:00"}, {"start": "09:00", "end": "24:00"},
                {**WINDOW, "timezone": "UTC"}, {**WINDOW, "weekdays": ["mon"]}, {}, True):
            with self.subTest(window=window), self.assertRaises(ValueError):
                NpmPublishRuleInput(**self.fields(), publishing_window=window)

    def test_alias_is_derived_from_exact_canonical_record(self):
        from serverware import operator_catalog_npm_publish as publish
        from serverware.operator_catalog_inputs import NpmPublishRuleInput
        from serverware.operator_catalog_schema import CatalogIntegrityError
        record = publish.record_fields(NpmPublishRuleInput(**self.fields()))
        record.update(id=activity_tests.RULE, route_id="operator." + activity_tests.RULE, status="active")
        self.assertEqual(publish.route_ids(record), (record["route_id"], record["route_id"] + ".metadata"))
        for changes in ({"route_id": record["route_id"] + ".metadata"}, {"id": "not-a-uuid"},
                {"metadata_route_id": "chosen"}, {"methods": ["GET", "PUT"]}):
            with self.subTest(changes=changes), self.assertRaises(CatalogIntegrityError):
                publish.route_ids({**record, **changes})
        catalog = {"credentials": [{"id": activity_tests.CREDENTIAL, "auth_type": "bearer"}],
            "applications": [{"id": activity_tests.APPLICATION, "principal_id": "principal"}],
            "access_rules": [record]}
        from serverware import operator_catalog_activity
        routes = operator_catalog_activity._indexes(catalog)[2]
        self.assertEqual(set(routes), set(publish.route_ids(record)))
        duplicate = {**record, "id": activity_tests.OTHER_RULE, "operation_bundle": "not-publish",
            "route_id": record["route_id"] + ".metadata"}
        with self.assertRaises(ValueError):
            operator_catalog_activity._indexes({**catalog, "access_rules": [record, duplicate]})


class ConnectedNpmPublishCatalogTests(unittest.TestCase):
    def setUp(self):
        workspace.common.OperatorDemoPersistenceTests.setUp(self)
        self.environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = '["https://api.example.com","https://api.github.com","https://registry.npmjs.org"]'

    def worker(self, name):
        environment = dict(self.environment)
        if name == "destination":
            environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = '["https://api.example.com"]'
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90)
        if result.returncode != 0:
            self.fail("isolated npm publish catalog worker failed (exit " + str(result.returncode)
                + "): " + github_tests.worker_failure_summary(result))
        return json.loads(result.stdout)

    def test_signed_two_route_permission_and_window(self):
        self.assertTrue(self.worker("signed")["two_routes_one_permission"])

    def test_symmetric_overlap_and_old_metadata_compatibility(self):
        self.assertTrue(self.worker("overlap")["symmetric_overlap_without_legacy_broadening"])

    def test_exact_bindings_and_stale_cas(self):
        self.assertTrue(self.worker("bindings")["strict_binding_and_stale_cas"])

    def test_replace_rotate_and_revoke_both_routes(self):
        self.assertTrue(self.worker("revoke")["both_routes_revoked_together"])

    def test_existing_metadata_record_and_signed_route_are_unchanged(self):
        self.assertTrue(self.worker("retained")["old_metadata_unchanged"])

    def test_real_audit_policy_rollback_and_postcommit_publication_failure(self):
        self.assertTrue(self.worker("rollback")["rollback_and_postcommit_distinguished"])

    def test_exact_activity_alias_without_suffix_adoption(self):
        self.assertTrue(self.worker("activity")["exact_derived_alias_only"])

    def test_destination_disabled_does_not_grant(self):
        self.assertTrue(self.worker("destination")["destination_required"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        try:
            result = OPERATIONS[sys.argv[2]]()
        except Exception as error:
            print(json.dumps(github_tests.safe_worker_failure(error), sort_keys=True))
            raise SystemExit(1) from None
        print(json.dumps(result, sort_keys=True))
    else:
        unittest.main(verbosity=2)
