#!/usr/bin/env python3
"""Focused common-app contracts, real constraints and isolated catalog lifecycle.

No provider credentials or contact. The lifecycle child uses real SQLite,
encryption, signing and audit; only gate health observation is substituted.
"""
from copy import deepcopy
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import operator_common_apps as common
from serverware import operator_catalog_inputs as inputs
from serverware import operator_catalog_policy as policy
from serverware import operator_catalog_schema as schema

APP_ID = "00000000-0000-4000-8000-000000000001"
CREDENTIAL_ID = "00000000-0000-4000-8000-000000000002"
RULE_ID = "00000000-0000-4000-8000-000000000003"
REVIEW = {"expected_revision": 1, "expected_policy_hash": "sha256:" + "0" * 64}


def scope_for(spec):
    result = {field["key"]: field.get("default", field.get("placeholder")) for field in spec["scope_fields"]}
    if "model" in result:
        result["model"] = "fixture/fixture-model" if spec["origin"] == "https://openrouter.ai" else "fixture-model"
    return result


def fixture(app, spec):
    payload = inputs.CommonAppRuleInput(**REVIEW, name="Common app fixture", application_id=APP_ID,
        credential_id=CREDENTIAL_ID, app_preset=app["id"], operation=spec["id"], scope=scope_for(spec))
    rule = common.record_fields(payload)
    rule.update(id=RULE_ID, route_id="operator." + RULE_ID, status="active")
    credential = {"id": CREDENTIAL_ID, "app_preset": app["id"], "auth_type": app["auth_type"],
        "header_name": app["header_name"], "provider_subject": "common-fixture", "status": "active"}
    application = {"id": APP_ID, "principal_id": "agent:operator-demo:" + APP_ID,
        "token_sha256": "sha256:" + "1" * 64, "token_expires_at_epoch_ms": 2000000000000,
        "status": "active"}
    bundle = policy.render({"credentials": [credential], "applications": [application],
        "access_rules": [rule]}, 1, "sha256:" + "2" * 64)
    return rule, credential, bundle


def flow_for(body, url, headers=None):
    return SimpleNamespace(metadata={}, request=SimpleNamespace(pretty_url=url,
        raw_content=json.dumps(body).encode() if body is not None else b"",
        headers={"content-type": "application/json", **(headers or {})}))


class RegistryTests(unittest.TestCase):
    def test_cloudflare_retained_profiles_render_identically(self):
        # Captured from the existing profiles before adding the SDK versions.
        expected = {"zones": "1f2f8340d034d412768d91ecbbcbc3439deac0332629a9bb9b6733a8631f58f8",
            "dns_records": "c177d3c145d5feb5f501c8f00f74486516cd62894d662d61c80aea0f711f89d2"}
        app = common.preset("cloudflare")
        for identifier, digest in expected.items():
            _, spec = common.operation("cloudflare", identifier)
            rule, credential, bundle = fixture(app, spec)
            common.validate_rule(rule, credential)
            encoded = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(hashlib.sha256(encoded).hexdigest(), digest)
            self.assertIs(spec["available_for_creation"], False)

    def test_cloudflare_sdk_profiles_admit_only_known_headers_on_exact_bodyless_reads(self):
        from serverware import adapters, policy_bundle
        headers = {"accept": "application/json", "user-agent": "Cloudflare/Python 5.9.0",
            "api-version": "2026-10-15", "x-stainless-lang": "python",
            "x-stainless-package-version": "5.9.0", "x-stainless-os": "Linux",
            "x-stainless-arch": "x64", "x-stainless-runtime": "CPython",
            "x-stainless-runtime-version": "3.12.3", "x-stainless-async": "false",
            "x-stainless-retry-count": "0", "x-stainless-read-timeout": "30"}
        for identifier in ("zones_sdk_v1", "dns_records_sdk_v1"):
            app, spec = common.operation("cloudflare", identifier)
            rule, credential, bundle = fixture(app, spec)
            snapshot = policy_bundle.compile_policy_bundle(bundle, verify_signature=False, validate_schema=True)
            route = snapshot.routes[0]
            request = route.adapter_config["request"]
            self.assertEqual((request["bodyMode"], request["maxBodyBytes"], request["allowedMediaTypes"]),
                ("none", 0, []))
            self.assertEqual(bundle["routes"][0]["credentialHeader"],
                {"mode": "replaceExact", "expectedValue": "Bearer serverware-cloudflare-placeholder-v1"})
            adapter = adapters.get_adapter("generic.rest")

            def admit(*, body=b"", extra=None, query=""):
                flow = SimpleNamespace(metadata={}, request=SimpleNamespace(method="GET",
                    pretty_url=rule["upstream_url"] + query, raw_content=body,
                    headers={**headers, **(extra or {})}))
                return adapter.validate_request(flow, route, {})

            self.assertTrue(admit().allowed)
            self.assertTrue(admit(query="?page=2&per_page=5").allowed)
            self.assertFalse(admit(body=b"{}").allowed)
            self.assertFalse(admit(extra={"content-type": "application/json"}).allowed)
            for name in ("x-auth-key", "x-auth-email", "x-auth-user-service-key", "cf-account-id",
                    "x-stainless-raw-response", "x-unreviewed-header"):
                with self.subTest(operation=identifier, header=name):
                    self.assertFalse(admit(extra={name: "unreviewed"}).allowed)
            self.assertFalse(admit(query="?account.id=unreviewed").allowed)
            principal = "agent:operator-demo:" + APP_ID
            target = rule["upstream_url"].removeprefix("https://api.cloudflare.com")
            self.assertIsNone(snapshot.match_route("https", "api.cloudflare.com", 443, "POST", target, principal))
            self.assertIsNone(snapshot.match_route("https", "api.cloudflare.com", 443, "GET", target + "/other", principal))
            with self.assertRaises(schema.CatalogIntegrityError):
                common.validate_rule({**rule, "placeholder": "Bearer unexpected"}, credential)
            _, old = common.operation("cloudflare", identifier.removesuffix("_sdk_v1"))
            old_route = policy_bundle.compile_policy_bundle(fixture(app, old)[2],
                verify_signature=False, validate_schema=True).routes[0]
            old_flow = SimpleNamespace(metadata={}, request=SimpleNamespace(method="GET",
                pretty_url=rule["upstream_url"], raw_content=b"", headers=headers))
            self.assertFalse(adapter.validate_request(old_flow, old_route, {}).allowed)

    def test_cloudflare_capability_keeps_legacy_descriptors_out_of_new_choices(self):
        from serverware import operator_demo
        with patch.object(operator_demo, "settings", return_value={"allowed_upstreams": ["https://api.cloudflare.com"]}):
            capability = common.capability()
        app = next(item for item in capability["presets"] if item["id"] == "cloudflare")
        self.assertEqual([item["id"] for item in app["operations"]],
            ["zones_sdk_v1", "dns_records_sdk_v1", "zones", "dns_records"])
        self.assertEqual([item["id"] for item in app["operations"] if item["available_for_creation"]],
            ["zones_sdk_v1", "dns_records_sdk_v1"])
        self.assertEqual(sum(item["available_for_creation"] for app in capability["presets"]
            for item in app["operations"]), 15)

    def test_common_app_post_has_exact_profile_and_body_route_admission(self):
        from serverware import operator_demo
        from serverware.operator_catalog_api import MUTATION_PATHS, router
        path = "/api/operator-demo/access-rules/common-app"
        with patch.object(operator_demo, "active", return_value=True):
            self.assertTrue(operator_demo.active())
            self.assertTrue(operator_demo.request_allowed("POST", path))
            for method in ("GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE"):
                self.assertFalse(operator_demo.request_allowed(method, path), method)
            for nearby in (path + "/", path + "/other", path + "-other"):
                self.assertFalse(operator_demo.request_allowed("POST", nearby), nearby)
        self.assertIn(path, MUTATION_PATHS)
        self.assertEqual([route.methods for route in router.routes if route.path == path], [{"POST"}])
        # Exercise the actual middleware classifier without booting a server.
        tree = ast.parse((ROOT / "serverware/app.py").read_text())
        selected = [node for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "_OPERATOR_CATALOG_BODY_POST_PATHS"
                for target in node.targets) or isinstance(node, ast.FunctionDef)
            and node.name == "_operator_catalog_body_is_route_owned"]
        self.assertEqual(len(selected), 2)
        namespace = {}
        exec(compile(ast.Module(body=selected, type_ignores=[]), "<actual-body-classifier>", "exec"), namespace)
        owns = namespace["_operator_catalog_body_is_route_owned"]
        self.assertTrue(owns("POST", path, operator_active=True))
        self.assertFalse(owns("POST", path, operator_active=False))
        self.assertFalse(owns("GET", path, operator_active=True))
        self.assertFalse(owns("POST", path + "/other", operator_active=True))

    def test_every_preset_compiles_and_examples_pass_actual_constraints(self):
        from serverware import constraints, policy_bundle
        identifiers = [app["id"] for app in common.presets()]
        self.assertEqual(len(identifiers), 12)
        self.assertEqual(len(set(identifiers)), 12)
        count = 0
        for app in common.presets():
            for spec in app["operations"]:
                with self.subTest(app=app["id"], operation=spec["id"]):
                    rule, _, bundle = fixture(app, spec)
                    policy_bundle.compile_policy_bundle(bundle, verify_signature=False, validate_schema=True)
                    route = bundle["routes"][0]
                    self.assertEqual(route["match"]["paths"], [rule["upstream_url"].split(spec["origin"])[1]])
                    self.assertEqual(route["credentialHeader"]["expectedValue"], app["placeholder"])
                    self.assertEqual(route["adapter"]["config"]["request"]["discardHeaders"], ["accept-encoding"])
                    body = common.resolve(spec.get("example_body"), rule["scope"])
                    query = common.resolve(spec.get("example_query", {}), rule["scope"])
                    headers = {key.lower(): value for key, value in spec.get("request_headers", {}).items()}
                    flow = flow_for(body, rule["upstream_url"] + ("?" + urlencode(sorted(query.items())) if query else ""), headers)
                    for constraint in route["constraints"]:
                        if constraint["type"] == "jsonBody":
                            self.assertTrue(constraints._enforce_json_body(constraint, flow).allowed)
                            extra = {**body, "unreviewed_authority": True}
                            self.assertFalse(constraints._enforce_json_body(constraint, flow_for(extra, rule["upstream_url"])).allowed)
                            self.assertFalse(constraints._enforce_json_body(constraint, flow_for(None, rule["upstream_url"])).allowed)
                    rules = route["adapter"]["config"]["request"]["valueRules"]
                    if rules:
                        constraint = {"type": "requestValue", "rules": rules}
                        self.assertTrue(constraints._enforce_request_value(constraint, flow, {}).allowed)
                        self.assertFalse(constraints._enforce_request_value(constraint,
                            flow_for(body, rule["upstream_url"]), {}).allowed)
                    count += 1
        self.assertGreaterEqual(count, 15)

    def test_scope_body_and_marker_tampering_are_refused(self):
        from serverware import constraints
        for identifier in ("openai", "anthropic", "gemini", "openrouter", "slack", "discord", "resend"):
            app = common.preset(identifier)
            spec = app["operations"][0]
            rule, credential, bundle = fixture(app, spec)
            for key, value in (("methods", ["DELETE"]), ("upstream_url", "https://elsewhere.example/path"),
                    ("response_mode", "unfiltered_json"), ("credential_input", "insert"),
                    ("placeholder", "arbitrary-token"), ("request_fields", ["arbitrary"])):
                changed = {**rule, key: value}
                with self.assertRaises(schema.CatalogIntegrityError):
                    common.validate_rule(changed, credential)
            wrong = {**credential, "app_preset": "stripe"}
            with self.assertRaises(schema.CatalogIntegrityError):
                common.validate_rule(rule, wrong)
            body = common.resolve(spec["example_body"], rule["scope"])
            body_constraint = next(item for item in bundle["routes"][0]["constraints"] if item["type"] == "jsonBody")
            changes = {"openai": {"model": "different", "max_output_tokens": 999999, "stream": True, "store": True},
                "anthropic": {"model": "different", "max_tokens": 999999, "stream": True},
                "openrouter": {"model": "different", "max_tokens": 999999, "stream": True},
                "gemini": {"generationConfig": {"maxOutputTokens": 999999}},
                "slack": {"channel": "C9999999999", "unfurl_links": True},
                "discord": {"allowed_mentions": {"parse": ["everyone"]}},
                "resend": {"to": "other@example.com", "from": "other@example.com"}}[identifier]
            for key, value in changes.items():
                with self.subTest(app=identifier, field=key):
                    self.assertFalse(constraints._enforce_json_body(body_constraint,
                        flow_for({**body, key: value}, rule["upstream_url"])).allowed)

    def test_inputs_are_closed_and_legacy_credential_stays_unmarked(self):
        base = {**REVIEW, "name": "Service token", "auth_type": "bearer", "secret": "synthetic-key"}
        self.assertIsNone(inputs.CredentialInput(**base).app_preset)
        self.assertNotIn("app_preset", inputs.CredentialInput(**base).model_dump())
        for marker in (None, "unknown", "", False):
            with self.assertRaises(ValueError):
                inputs.CredentialInput(**base, app_preset=marker)
        with self.assertRaises(ValueError):
            inputs.CredentialInput(**base, app_preset="anthropic")
        for app in common.presets():
            accepted = inputs.CredentialInput(**{**base, "auth_type": app["auth_type"],
                "header_name": app["header_name"], "app_preset": app["id"]})
            self.assertEqual(accepted.app_preset, app["id"])
            spec = app["operations"][0]
            values = {**REVIEW, "name": "Scoped service", "application_id": APP_ID,
                "credential_id": CREDENTIAL_ID, "app_preset": app["id"], "operation": spec["id"],
                "scope": scope_for(spec)}
            for change in ({"upstream_url": "https://other.example"}, {"methods": ["DELETE"]},
                    {"scope": {**values["scope"], "extra": "broad"}}, {"operation": "all"}):
                with self.assertRaises(ValueError):
                    inputs.CommonAppRuleInput(**{**values, **change})
        with self.assertRaises(ValueError):
            inputs.CommonAppRuleInput(**{**values, "app_preset": "openai", "operation": "responses_text_v1",
                "scope": {"model": "fixture", "max_output_tokens": True}})

    def test_identity_metadata_rotation_join_and_discord_prefix(self):
        for app in common.presets():
            _, record, bundle = fixture(app, app["operations"][0])
            metadata = {"app_preset": app["id"]}
            if app["auth_type"] == "header":
                metadata["injection_name"] = app["header_name"]
            self.assertTrue(common.validate_credential(record, metadata))
            for changed in ({}, {"app_preset": "unknown"}, {**metadata, "connection_type": "github_token_v1"}):
                with self.assertRaises(schema.CatalogIntegrityError):
                    common.validate_credential(record, changed)
            if app["id"] == "discord":
                self.assertEqual(bundle["credentials"][0]["injection"],
                    {"type": "bearer", "header": "Authorization", "prefix": "Bot "})

    def test_capabilities_do_not_approve_destinations_or_mutate_registry(self):
        from serverware import operator_demo
        before = deepcopy(common.presets())
        with patch.object(operator_demo, "settings", return_value={"allowed_upstreams": ["https://api.openai.com"]}):
            value = common.capability()
        self.assertEqual(value["schema"], common.SCHEMA)
        self.assertEqual([item["id"] for item in value["presets"] if item["destination_allowed"]], ["openai"])
        self.assertEqual(common.presets(), before)
        value["presets"][0]["operations"][0]["request_fields"].append("mutated")
        self.assertEqual(common.presets(), before)


def lifecycle_worker():
    import test_operator_catalog_github as fixture_module
    from serverware import operator_demo
    f = fixture_module.Fixture()
    app = f.application()
    for identifier in ("openai", "anthropic", "discord"):
        descriptor = common.preset(identifier)
        spec = descriptor["operations"][0]
        with patch.object(f.store, "loaded_gate_status", return_value=None):
            credential = f.call(f.mutations.create_credential, f.inputs.CredentialInput(**f.review(),
                name="Synthetic " + identifier, auth_type=descriptor["auth_type"],
                header_name=descriptor["header_name"], app_preset=identifier,
                secret="synthetic-common-app-private-key"), fixture_module.ACTOR)["credential"]
            fields = {**f.review(), "name": "Scoped " + identifier, "application_id": app["id"],
                "credential_id": credential["id"], "app_preset": identifier,
                "operation": spec["id"], "scope": scope_for(spec)}
            before = f.snapshot()
            with patch.object(operator_demo, "settings", return_value={"allowed_upstreams": []}):
                with unittest.TestCase().assertRaises(ValueError):
                    f.mutations.create_common_app_rule(f.inputs.CommonAppRuleInput(**fields), fixture_module.ACTOR)
            assert f.snapshot() == before
            wrong_app = common.preset("anthropic" if identifier == "openai" else "openai")
            wrong_spec = wrong_app["operations"][0]
            mismatch = {**fields, "app_preset": wrong_app["id"], "operation": wrong_spec["id"],
                "scope": scope_for(wrong_spec)}
            with unittest.TestCase().assertRaises(ValueError):
                f.call(f.mutations.create_common_app_rule, f.inputs.CommonAppRuleInput(**mismatch), fixture_module.ACTOR)
            assert f.snapshot() == before
            created = f.call(f.mutations.create_common_app_rule, f.inputs.CommonAppRuleInput(**fields), fixture_module.ACTOR)
            assert created["access_rule"]["app_preset"] == identifier
            before = f.snapshot()
            with unittest.TestCase().assertRaises(schema.CatalogConflict):
                f.call(f.mutations.create_common_app_rule, f.inputs.CommonAppRuleInput(**fields), fixture_module.ACTOR)
            assert f.snapshot() == before
            signed = f.signed()
            replacement = f.call(f.mutations.replace_credential_key,
                f.inputs.ReplaceCredentialKeyInput(**f.review(), id=credential["id"],
                    expected_credential_generation=1, secret="synthetic-common-app-replacement"), fixture_module.ACTOR)
            assert replacement["credential"]["app_preset"] == identifier
            assert replacement["credential"]["credential_generation"] == 2
            assert f.signed() == signed
            core = f.db.get_credential(credential["id"], include_secret=True)
            assert core["secret"] == "synthetic-common-app-replacement"
            assert core["metadata"]["app_preset"] == identifier
            before = f.snapshot()
            with unittest.TestCase().assertRaises(schema.CatalogConflict):
                f.call(f.mutations.revoke_credential, f.target(credential["id"]), fixture_module.ACTOR)
            assert f.snapshot() == before
            f.call(f.mutations.revoke_rule, f.target(created["access_rule"]["id"]), fixture_module.ACTOR)
            receipt = f.call(f.mutations.revoke_credential, f.target(credential["id"]), fixture_module.ACTOR)
            assert not receipt.get("affected_rule_ids")
            assert receipt["credential"]["app_preset"] == identifier
    retained = f.catalog()
    assert all(row["status"] == "revoked" for row in retained["credentials"])
    assert all(row["status"] == "revoked" for row in retained["access_rules"])
    assert f.db.verify_audit_chain()["ok"]
    serialized = json.dumps(retained)
    assert "synthetic-common-app-private-key" not in serialized
    assert "synthetic-common-app-replacement" not in serialized
    before = f.snapshot()
    f.store.initialize()
    assert f.snapshot() == before
    return {"encrypted_lifecycle_providers": 3}


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        import test_operator_catalog_github as fixture_module
        fixture_module.OperatorCatalogGithubTests.setUp(self)
        self.environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = json.dumps(
            ["https://api.example.com", "https://api.openai.com", "https://api.anthropic.com", "https://discord.com"])

    def test_actual_encrypted_catalog_rotation_revoke_signatures_and_audit(self):
        import test_operator_catalog_github as fixture_module
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker"],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, fixture_module.worker_failure_summary(result))
        self.assertEqual(json.loads(result.stdout)["encrypted_lifecycle_providers"], 3)


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        import test_operator_catalog_github as fixture_module
        os.umask(0o077)
        try:
            print(json.dumps(lifecycle_worker()))
        except Exception as error:
            print(json.dumps(fixture_module.safe_worker_failure(error)))
            raise SystemExit(1) from None
    else:
        unittest.main(verbosity=2)
