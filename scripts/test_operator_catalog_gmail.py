#!/usr/bin/env python3
"""Catalog-only Gmail bundle checks with real SQLite/signing and guarded ASGI.

The synthetic already-verified account fixture is not consent, provider, client
compatibility or proxy-runtime proof. No admission/lifecycle guard is mocked;
only gate observation is stubbed, and provider transport fails on contact.
Run only in the authorized bounded network-none lane.

Provider shape references (not contacted by this test):
https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list
https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get
Pagination/returned-ID/body preservation needs the separate paired runtime job;
these tests establish the catalog's single-route authority and persisted contract.
"""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_operator_catalog_google as google
import test_operator_google_consent as consent
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = "/api/operator-demo/access-rules/gmail-read"
ACTOR = "operator-gmail-bundle-test"
READ_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


class Fixture(google.Fixture):
    request = consent.Fixture.request
    _request = consent.Fixture._request

    def http(self):
        from serverware import app, oauth
        self.app, self.oauth, self.cookie = app, oauth, None

    def fields(self, application, **changes):
        result = {**workspace.review(self.db, self.store, self.schema),
            "name": "Read Gmail messages", "application_id": application["id"],
            "credential_id": self.record["id"], "operation_bundle": "gmail_read_v1"}
        result.update(changes)
        return result

    def bundle(self, application, **changes):
        payload = self.inputs.GmailReadRuleInput(**self.fields(application, **changes))
        return self.call(self.mutations.create_gmail_rule, payload, ACTOR)

    def signed(self):
        raw = json.loads(self.config.POLICY_BUNDLE_PATH.read_bytes())
        compiled = self.bundles.compile_policy_bundle(raw, verify_signature=True, validate_schema=True)
        assert compiled.hash == self.store.get_policy_high_water()["policy_hash"]
        return raw


def strict_input():
    f = Fixture()
    application = f.application()
    fields = f.fields(application)
    admitted = f.inputs.GmailReadRuleInput(**fields)
    assert admitted.age_policy.model_dump() == {"mode": "unrestricted"}
    cases = [{key: value} for key, value in (
        ("operation_bundle", "gmail_read_v2"), ("operation_bundle", None),
        ("age_policy", None), ("age_policy", {}),
        ("age_policy", {"mode": "maxAgeDays", "maxAgeDays": 30}),
        ("age_policy", {"mode": "unrestricted", "maxAgeDays": 30}),
        ("upstream_url", "https://gmail.googleapis.com/gmail/v1/users/me/history"),
        ("methods", ["POST"]), ("request_fields", []), ("response_fields", ["id"]),
        ("response_mode", "unfiltered_json_or_empty_v2"), ("query_keys", ["fields"]),
        ("allowed_headers", ["cookie"]), ("request_body_mode", "preserve_json_v1"),
        ("placeholder", None), ("application_id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
        ("query_mode", "orderedFormV1"), ("query_mode", None),
    )]
    before = f.snapshot()
    for changes in cases:
        google.refused(lambda: f.inputs.GmailReadRuleInput(**{**fields, **changes}), ValueError)
    missing = dict(fields)
    missing.pop("operation_bundle")
    google.refused(lambda: f.inputs.GmailReadRuleInput(**missing), ValueError)
    # The pre-existing generic endpoint must not silently consume a bundle.
    google.refused(lambda: f.inputs.RuleInput(**fields), ValueError)
    assert f.snapshot() == before
    return {"input_refusals": len(cases) + 2, "age_off_explicit": True}


def signed_bundle():
    f = Fixture()
    application = f.application()
    core = f.core()
    result = f.bundle(application, credential_input="replace_exact", placeholder="Bearer SERVERWARE_DUMMY")
    rule = result["access_rule"]
    assert rule["route_id"] == "operator." + rule["id"]
    assert rule["operation_bundle"] == "gmail_read_v1" and rule["age_policy"] == {"mode": "unrestricted"}
    assert rule["response_mode"] == "gmail_read_json_v1" and rule["response_fields"] == []
    assert rule["query_mode"] == "orderedFormV1"
    assert result["policy"]["activation"] == "pending"
    raw = f.signed()
    routes = [route for route in raw["routes"] if route["id"] == rule["route_id"]]
    assert len(routes) == len(raw["routes"]) == 1
    route = routes[0]
    assert route["match"] == {"scheme": "https", "host": "gmail.googleapis.com", "port": 443,
        "methods": ["GET"], "paths": ["/gmail/v1/users/me/messages", "/gmail/v1/users/me/messages/{message_id}"]}
    assert route["credentialRef"] == f.record["id"] and route["principals"] == [application["principal_id"]]
    assert route["credentialHeader"] == {"mode": "replaceExact", "expectedValue": "Bearer SERVERWARE_DUMMY"}
    assert "jit" not in route
    cfg = route["adapter"]["config"]
    assert route["adapter"]["type"] == "gmail.read.v1"
    assert set(cfg) == {"credentialBinding", "request", "agePolicy", "response"}
    assert cfg["credentialBinding"] == {"credentialType": "oauth2", "provider": "google",
        "subjects": [f.record["provider_subject"]], "clientIds": [f.profile.client_id], "requiredScopes": [READ_SCOPE]}
    assert cfg["agePolicy"] == {"mode": "unrestricted"}
    assert cfg["request"] == {"allowedHeaders": ["accept", "user-agent", "x-goog-api-client"],
        "discardHeaders": ["accept-encoding"], "allowedQueryKeys": ["alt", "format", "includeSpamTrash", "labelIds",
            "maxResults", "metadataHeaders", "pageToken", "prettyPrint", "q"],
        "allowedMediaTypes": [], "maxBodyBytes": 0, "valueRules": [], "queryMode": "orderedFormV1"}
    assert cfg["response"] == {"mode": "gmailReadJsonV1", "maxBodyBytes": 1048576,
        "contentTypes": ["application/json"], "allowedHeaders": [], "error": {
            "mode": "gmailReadJsonV1", "maxBodyBytes": 65536, "contentTypes": ["application/json"],
            "allowedHeaders": [], "onInvalid": "block"}}
    assert route["constraints"] == [{"id": rule["route_id"] + ".envelope", "type": "responseEnvelope",
        "phase": "response", "statusCodes": [200, 400, 401, 403, 404, 429, 500, 502, 503, 504],
        "bodyPresence": "required", "unlistedHeaderPolicy": "discardUnselectedV1",
        "contentTypes": ["application/json"], "allowedResponseHeaderNames": [], "responseHeaderRules": []}]
    assert raw["credentials"][0]["scopes"] == list(f.profile.scopes)
    assert raw["credentials"][0]["injection"] == {"type": "bearer", "header": "Authorization", "field": "access_token"}
    assert f.core() == core
    status = f.call(f.mutations.catalog_status)
    assert status["capabilities"]["operation_bundles"] == [{
        "operation_bundle": "gmail_read_v1", "create_path": ENDPOINT,
        "credential_type": "google_oauth", "permission_preset": "gmail_readonly",
        "api_origin": "https://gmail.googleapis.com", "methods": ["GET"],
        "paths": ["/gmail/v1/users/me/messages", "/gmail/v1/users/me/messages/{message_id}"],
        "query_mode": "orderedFormV1", "age_policy": {"mode": "unrestricted"},
        "age_policy_options": [{"mode": "unrestricted"},
            {"mode": "recent_internal_date_v1", "min_age_days": 1,
                "max_age_days": 3650, "max_list_results": 32}],
        "response_mode": "gmail_read_json_v1", "response_contract": {
            "mode": "gmailReadJsonV1", "body_presence": "required",
            "content_types": ["application/json"], "success_status_codes": [200],
            "error_status_codes": [400, 401, 403, 404, 429, 500, 502, 503, 504],
            "max_body_bytes": 1048576, "max_error_body_bytes": 65536,
            "unlisted_header_policy": "discardUnselectedV1"}}]
    assert "gmail_read_json_v1" not in status["capabilities"]["response_modes"]
    for secret in (google.ACCESS_TOKEN, google.REFRESH_TOKEN, google.CLIENT_SECRET):
        assert secret not in json.dumps(status) and secret not in json.dumps(raw)
    return {"one_route_two_operations": True, "closed_source_capability": True}


def recent_bundle():
    f = Fixture()
    old = f.bundle(f.application())["access_rule"]
    old_route = next(row for row in f.signed()["routes"] if row["id"] == old["route_id"])
    old_bytes = f.bundles.canonical_json(old_route)
    core = f.core()
    selected = {"mode": "recent_internal_date_v1", "max_age_days": 30}
    rule = f.bundle(f.application(), age_policy=selected)["access_rule"]
    assert rule["age_policy"] == selected and rule["query_mode"] == "orderedFormV1"
    raw = f.signed()
    route = next(row for row in raw["routes"] if row["id"] == rule["route_id"])
    assert route["adapter"]["config"]["agePolicy"] == {
        "mode": "recent_internal_date_v1", "maxAgeDays": 30}
    for key in ("request", "response", "credentialBinding"):
        assert route["adapter"]["config"][key] == old_route["adapter"]["config"][key]
    assert route["constraints"] == [f.bundles.gmail_read_response_envelope(rule["route_id"] + ".envelope")]
    assert f.bundles.canonical_json(next(row for row in raw["routes"] if row["id"] == old["route_id"])) == old_bytes
    public = f.call(f.mutations.catalog_status)
    assert next(row for row in public["access_rules"] if row["id"] == rule["id"])["age_policy"] == selected
    assert f.core() == core

    invalid = [None, {}, {"mode": "recent_internal_date_v1"},
        {"mode": "unrestricted", "maxAgeDays": 30},
        {"mode": "recent_internal_date_v1", "max_age_days": 30},
        {"mode": "recent_internal_date_v1", "maxAgeDays": 30, "cacheTtlSeconds": 60}]
    invalid += [{"mode": "recent_internal_date_v1", "maxAgeDays": days}
        for days in (None, True, False, 0, -1, 3651, "30", 30.0)]
    route_index = next(index for index, row in enumerate(raw["routes"]) if row["id"] == rule["route_id"])
    for schema in (False, True):
        for age in invalid:
            candidate = deepcopy(raw)
            candidate["routes"][route_index]["adapter"]["config"]["agePolicy"] = age
            google.refused(lambda: f.bundles.compile_policy_bundle(candidate,
                verify_signature=False, validate_schema=schema), f.bundles.PolicyBundleError)
        for days in (1, 3650):
            candidate = deepcopy(raw)
            candidate["routes"][route_index]["adapter"]["config"]["agePolicy"]["maxAgeDays"] = days
            f.bundles.compile_policy_bundle(candidate, verify_signature=False, validate_schema=schema)
        candidate = deepcopy(raw)
        candidate["routes"][route_index]["adapter"]["config"]["request"] = f.bundles.provider_request_profile("gmail.read.v1")
        google.refused(lambda: f.bundles.compile_policy_bundle(candidate,
            verify_signature=False, validate_schema=schema), f.bundles.PolicyBundleError)

    # The Python prototype cannot prove fresh age evidence, including when its
    # response hooks are invoked directly. It must not act as an age bypass.
    from serverware import adapters
    compiled = f.bundles.compile_policy_bundle(raw, verify_signature=True, validate_schema=True)
    policy = next(row for row in compiled.routes if row.id == rule["route_id"])
    adapter = adapters.get_adapter("gmail.read.v1")
    for check in (adapter.validate_request, adapter.prepare_response, adapter.validate_response):
        decision = check(SimpleNamespace(), policy, {})
        assert not decision.allowed and decision.payload["error"] == "gmail_read_age_evidence_unsupported"
    return {"recent_policy_signed": True, "unrestricted_route_bytes_unchanged": True,
        "compiler_refusals": 2 * (len(invalid) + 1), "python_prototype_refused": True}


def legacy_retained():
    f = Fixture()
    application = f.application()
    old = f.rule(application)["access_rule"]
    before_collision = f.snapshot()
    google.refused(lambda: f.bundle(application), f.bundles.PolicyBundleError)
    assert f.snapshot() == before_collision
    pre_query = f.bundle(f.application())["access_rule"]
    # Construct the actual previously supported persisted shape. This is only
    # fixture setup, not an API downgrade path or migration under test.
    with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        catalog = f.schema.read_catalog(conn)
        record = next(row for row in catalog["access_rules"] if row["id"] == pre_query["id"])
        record.pop("query_mode")
        record["allowed_headers"] = ["accept", "accept-encoding", "user-agent", "x-goog-api-client"]
        f.schema.save_resource(conn, "access_rules", record)
        f.mutations.policy.publish(conn)
        f.schema.advance_revision(conn, catalog["revision"])
        conn.commit()
        f.store.materialize()
    before_catalog = workspace.catalog(f.db, f.schema)
    old_record = next(row for row in before_catalog["access_rules"] if row["id"] == old["id"])
    old_route = next(row for row in f.signed()["routes"] if row["id"] == old["route_id"])
    pre_query_record = next(row for row in before_catalog["access_rules"] if row["id"] == pre_query["id"])
    pre_query_route = next(row for row in f.signed()["routes"] if row["id"] == pre_query["route_id"])
    assert "query_mode" not in pre_query_record
    assert "queryMode" not in pre_query_route["adapter"]["config"]["request"]
    caps = f.call(f.mutations.catalog_status)["capabilities"]
    f.bundle(f.application(), age_policy={"mode": "recent_internal_date_v1", "max_age_days": 7})
    assert next(row for row in f.signed()["routes"] if row["id"] == old["route_id"]) == old_route
    assert next(row for row in workspace.catalog(f.db, f.schema)["access_rules"] if row["id"] == old["id"]) == old_record
    assert next(row for row in f.signed()["routes"] if row["id"] == pre_query["route_id"]) == pre_query_route
    assert next(row for row in workspace.catalog(f.db, f.schema)["access_rules"] if row["id"] == pre_query["id"]) == pre_query_record
    assert "operation_bundle" not in old_record and "age_policy" not in old_record
    assert f.call(f.mutations.catalog_status)["capabilities"] == caps
    public_old = next(row for row in f.call(f.mutations.catalog_status)["access_rules"] if row["id"] == pre_query["id"])
    assert "query_mode" not in public_old
    before = f.snapshot()
    f.store.initialize()
    assert f.snapshot() == before
    return {"legacy_rule_unchanged": True, "reinitialize_unchanged": True}


def refused_bindings():
    f = Fixture()
    application = f.application()
    stale = f.inputs.GmailReadRuleInput(**f.fields(application))
    rule = f.bundle(application)["access_rule"]
    before = f.snapshot()
    google.refused(lambda: f.call(f.mutations.create_gmail_rule, stale, ACTOR), f.schema.CatalogConflict)
    assert f.snapshot() == before
    with closing(f.db.connect()) as conn:
        for changes in ({"operation_bundle": "gmail_read_v2"}, {"operation_bundle": None},
                {"age_policy": {"mode": "maxAgeDays", "maxAgeDays": 30}},
                {"upstream_url": google.GMAIL + "history"}, {"methods": ["POST"]},
                {"response_mode": "unfiltered_json_or_empty_v2"}, {"query_keys": ["fields"]},
                {"query_mode": None}, {"query_mode": "orderedFormV2"}):
            conn.execute("BEGIN IMMEDIATE")
            record = next(item for item in f.schema.read_catalog(conn)["access_rules"] if item["id"] == rule["id"])
            f.schema.save_resource(conn, "access_rules", {**record, **changes})
            google.refused(lambda: f.schema.validate_bindings(conn), f.schema.CatalogIntegrityError)
            bad = f.schema.read_catalog(conn)
            google.refused(lambda: f.mutations.policy.render(bad, 1, "sha256:" + "1" * 64), f.schema.CatalogIntegrityError)
            conn.rollback()
        conn.execute("BEGIN")
        assert f.google.require_lease_binding(conn, principal_id=application["principal_id"],
            route_id=rule["route_id"], credential_id=f.record["id"],
            core_credential=f.core(), profile=f.profile)["id"] == f.record["id"]
        conn.rollback()
        from serverware import operator_catalog_gmail
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE operator_catalog_oauth_profile SET binding_digest=?", ("sha256:" + "0" * 64,))
        google.refused(lambda: operator_catalog_gmail.capabilities(conn), f.schema.CatalogIntegrityError)
        conn.rollback()
        conn.execute("BEGIN")
        with patch.dict(os.environ, {"SERVERWARE_NATIVE_ENABLED": "1"}):
            google.refused(lambda: operator_catalog_gmail.capabilities(conn), f.profiles.OperatorGoogleProfileError)
        conn.rollback()
    assert f.snapshot() == before
    static = f.call(workspace.create_credential, f.db, f.store, f.schema, f.inputs, f.mutations)["credential"]
    before = f.snapshot()
    google.refused(lambda: f.bundle(application, credential_id=static["id"]), ValueError)
    assert f.snapshot() == before
    return {"persisted_contract_refusals": 9, "stale_cas_and_static_refused": True}


def disabled_capability():
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    before = workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    from serverware import operator_catalog_gmail
    with closing(db.connect()) as conn:
        google.refused(lambda: operator_catalog_gmail.capabilities(conn), schema.CatalogIntegrityError)
        conn.execute("BEGIN")
        assert operator_catalog_gmail.capabilities(conn) == []
        conn.rollback()
    with patch.object(store, "loaded_policy_hash", return_value=None):
        status = mutations.catalog_status()
    assert status["capabilities"]["operation_bundles"] == []
    assert status["capabilities"]["oauth"] is False and status["capabilities"]["google_oauth"] is None
    assert (workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()) == before
    return {"disabled_capability": True}


def shared_lifecycle():
    f = Fixture()
    first, second = f.application(), f.application()
    first_rule, second_rule = f.bundle(first)["access_rule"], f.bundle(second)["access_rule"]
    core = f.core()
    result = f.call(f.mutations.revoke_application, f.inputs.TargetInput(
        **workspace.review(f.db, f.store, f.schema), id=first["id"]), ACTOR)
    assert result["application"]["status"] == "revoked"
    catalog = workspace.catalog(f.db, f.schema)
    assert next(row for row in catalog["access_rules"] if row["id"] == first_rule["id"])["status"] == "revoked"
    assert next(row for row in catalog["access_rules"] if row["id"] == second_rule["id"])["status"] == "active"
    assert [route["id"] for route in f.signed()["routes"]] == [second_rule["route_id"]]
    old_principal = f.signed()["principals"][0]
    rotated = f.call(f.mutations.rotate_application_token, f.inputs.RotateApplicationInput(
        **workspace.review(f.db, f.store, f.schema), id=second["id"], token_lifetime_seconds=3600), ACTOR)
    assert rotated["application"]["token_generation"] == 2 and rotated["client_token"]
    assert f.signed()["principals"][0]["proxyAuthorization"]["tokenSha256"] != old_principal["proxyAuthorization"]["tokenSha256"]
    assert f.core() == core
    assert rotated["client_token"] not in json.dumps(f.call(f.mutations.catalog_status))
    return {"shared_account_retained": True, "rotation_republished": True}


def guarded_http():
    f = Fixture()
    application = f.application()
    f.http()
    fields = f.fields(application)
    before = f.snapshot()
    with patch.object(f.store, "loaded_policy_hash", return_value=None), patch.object(
            f.oauth, "request_bytes", side_effect=AssertionError("catalog must not contact provider")) as provider:
        assert f.request("POST", ENDPOINT, body=fields, auth=False)[0] == 401
        assert f.request("POST", ENDPOINT, body=fields, origin=False)[0] == 403
        assert f.request("POST", ENDPOINT, body={**fields, "methods": ["POST"]})[0] == 422
        for days in (True, 0, 3651, "30"):
            assert f.request("POST", ENDPOINT, body={**fields, "age_policy": {
                "mode": "recent_internal_date_v1", "max_age_days": days}})[0] == 422
        duplicate = json.dumps(fields)[:-1] + ',"operation_bundle":"gmail_read_v1"}'
        assert f.request("POST", ENDPOINT, body=duplicate.encode())[0] == 422
        assert f.request("POST", ENDPOINT, body=b" " * 4097)[0] == 413
        assert f.snapshot() == before
        code, raw, headers = f.request("POST", ENDPOINT, body=fields)
        assert code == 201
        result = json.loads(raw)
        assert result["access_rule"]["operation_bundle"] == "gmail_read_v1"
        assert [value for name, value in headers if name.lower() == b"cache-control"] == [b"no-store"]
        assert f.request("POST", ENDPOINT, body=fields)[0] == 409
        selected = {"mode": "recent_internal_date_v1", "max_age_days": 30}
        recent = f.fields(f.application(), age_policy=selected)
        code, raw, _ = f.request("POST", ENDPOINT, body=recent)
        assert code == 201 and json.loads(raw)["access_rule"]["age_policy"] == selected
        assert provider.call_count == 0
    return {"guarded_http": True, "provider_contacts": 0}


OPERATIONS = {"strict-input": strict_input, "signed-bundle": signed_bundle,
    "recent-bundle": recent_bundle,
    "legacy-retained": legacy_retained, "refused-bindings": refused_bindings,
    "shared-lifecycle": shared_lifecycle, "guarded-http": guarded_http,
    "disabled-capability": disabled_capability}


class OperatorCatalogGmailTests(unittest.TestCase):
    def setUp(self):
        consent.OperatorGoogleConsentTests.setUp(self)

    def worker(self, operation):
        environment = dict(self.environment)
        if operation == "disabled-capability":
            environment = {key: value for key, value in environment.items()
                if not key.startswith("SERVERWARE_GOOGLE_OAUTH_") and key != "SERVERWARE_OPERATOR_GOOGLE_PROFILE"}
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-35:]))
        return json.loads(result.stdout)

    def test_closed_input_rejects_age_and_generic_authority_overrides(self):
        self.assertEqual(self.worker("strict-input")["input_refusals"], 20)

    def test_one_signed_route_binds_both_reads_and_closed_source_capability(self):
        self.assertTrue(self.worker("signed-bundle")["one_route_two_operations"])

    def test_recent_policy_signed_compiled_and_prototype_fail_closed(self):
        result = self.worker("recent-bundle")
        self.assertTrue(result["recent_policy_signed"])
        self.assertTrue(result["unrestricted_route_bytes_unchanged"])
        self.assertTrue(result["python_prototype_refused"])

    def test_old_rule_render_and_repeat_initialization_are_unchanged(self):
        self.assertTrue(self.worker("legacy-retained")["legacy_rule_unchanged"])

    def test_unknown_persisted_bundle_stale_cas_and_wrong_credential_refuse(self):
        self.assertEqual(self.worker("refused-bindings")["persisted_contract_refusals"], 9)

    def test_disabled_profile_has_no_bundle_capability_or_store_changes(self):
        self.assertTrue(self.worker("disabled-capability")["disabled_capability"])

    def test_app_revoke_and_rotation_preserve_shared_google_account(self):
        self.assertTrue(self.worker("shared-lifecycle")["shared_account_retained"])

    def test_real_guarded_endpoint_refuses_bad_requests_without_provider_io(self):
        self.assertEqual(self.worker("guarded-http")["provider_contacts"], 0)


class GmailAgePolicyContractTests(unittest.TestCase):
    def test_strict_age_input_and_persisted_shape(self):
        from serverware import operator_catalog_gmail as gmail, operator_catalog_inputs as inputs
        from serverware.operator_catalog_schema import CatalogIntegrityError
        fields = {"expected_revision": 1, "expected_policy_hash": "sha256:" + "0" * 64,
            "name": "Gmail age fixture", "application_id": "00000000-0000-4000-8000-000000000001",
            "credential_id": "00000000-0000-4000-8000-000000000002", "operation_bundle": "gmail_read_v1"}
        omitted = inputs.GmailReadRuleInput(**fields)
        explicit = inputs.GmailReadRuleInput(**fields, age_policy={"mode": "unrestricted"})
        self.assertEqual(omitted.model_dump(), explicit.model_dump())
        self.assertEqual(omitted.age_policy.model_dump(), {"mode": "unrestricted"})
        for days in (1, 30, 3650):
            policy = {"mode": "recent_internal_date_v1", "max_age_days": days}
            value = inputs.GmailReadRuleInput(**fields, age_policy=policy)
            record = gmail.record_fields(value)
            self.assertEqual(value.age_policy.model_dump(), policy)
            self.assertEqual(gmail.public_fields(record)["age_policy"], policy)
            legacy = dict(record)
            legacy.pop("query_mode")
            legacy.update(gmail._derived_fields())
            with self.assertRaises(CatalogIntegrityError):
                gmail.validate_shape(legacy)
        invalid = [None, {}, {"mode": "recent_internal_date_v1"},
            {"mode": "unrestricted", "max_age_days": 30},
            {"mode": "recent_internal_date_v1", "maxAgeDays": 30},
            {"mode": "recent_internal_date_v1", "max_age_days": 30, "extra": True}]
        invalid += [{"mode": "recent_internal_date_v1", "max_age_days": days}
            for days in (None, True, False, 0, -1, 3651, "30", 30.0)]
        record = gmail.record_fields(omitted)
        for policy in invalid:
            with self.subTest(policy=policy):
                with self.assertRaises(ValueError):
                    inputs.GmailReadRuleInput(**fields, age_policy=policy)
                with self.assertRaises(CatalogIntegrityError):
                    gmail.validate_shape({**record, "age_policy": policy})

    def test_unrestricted_route_bytes_match_pre_change_fingerprints(self):
        from serverware import operator_catalog_gmail as gmail
        credential = {"id": "credential:test", "provider_subject": "subject:test", "oauth_client_id": "client:test"}
        original = {"operation_bundle": gmail.BUNDLE, "age_policy": {"mode": "unrestricted"}, "route_id": "route:test"}
        # Captured from both retained profiles before adding the new age mode.
        expected = {None: "fdab47ea1a8744c76e6ec4e2b86e71d4e465e360cc6431627237d8d17db0086a",
            gmail.QUERY_MODE: "9bca686dbbe526c4b12f37e41633aeb41ebd8acc2f16bab596cb66490b889dc7"}
        for mode, digest in expected.items():
            rule = {**original, **gmail._derived_fields(mode), **({"query_mode": mode} if mode else {})}
            encoded = json.dumps(gmail.render_route(rule, credential, "principal:test"),
                sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(hashlib.sha256(encoded).hexdigest(), digest)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
