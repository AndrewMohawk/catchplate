#!/usr/bin/env python3
"""Focused ECR catalog/compiled-policy checks; no credentials or provider I/O."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import ecr_publication_policy as wire
from serverware import operator_catalog_ecr as ecr
from serverware import operator_catalog_inputs as inputs
from serverware import operator_catalog_policy as catalog_policy
from serverware import operator_catalog_schema as schema
from serverware import policy_bundle

APP = "00000000-0000-4000-8000-000000000001"
CREDENTIAL = "00000000-0000-4000-8000-000000000002"
RULE = "00000000-0000-4000-8000-000000000003"
SUBJECT = "00000000-0000-4000-8000-000000000004"
PAYLOAD = {"expected_revision": 1, "expected_policy_hash": "sha256:" + "0" * 64,
    "name": "Release CI to exact ECR image", "application_id": APP, "credential_id": CREDENTIAL,
    "operation_bundle": ecr.BUNDLE, "registry_id": "123456789012", "region": "us-east-1",
    "repository_name": "example/service", "image_tag": "release-1", "approval_mode": "host_review_v1"}


def fixture():
    rule = ecr.record_fields(inputs.AwsEcrRuleInput(**PAYLOAD))
    rule.update(id=RULE, route_id="operator." + RULE, status="active")
    credential = {"id": CREDENTIAL, "name": "Stored AWS tuple", "auth_type": "aws_sigv4_v1",
        "header_name": None, "connection_type": "aws_sigv4_v1", "provider_subject": SUBJECT,
        "credential_kind": "long_term", "expires_at": None, "status": "active"}
    application = {"id": APP, "principal_id": "agent:operator-demo:" + APP, "status": "active",
        "token_sha256": "sha256:" + "1" * 64, "token_expires_at_epoch_ms": 2000000000000}
    with patch("serverware.operator_demo.settings", return_value={"allowed_upstreams": ["https://api.ecr.us-east-1.amazonaws.com"]}):
        raw = catalog_policy.render({"credentials": [credential], "applications": [application], "access_rules": [rule]},
            1, "sha256:" + "2" * 64)
    return rule, credential, raw


class EcrCatalogTests(unittest.TestCase):
    def test_typed_catalog_compiles_closed_signing_without_header_injection(self):
        rule, credential, raw = fixture()
        ecr.validate_rule(rule, credential)
        self.assertIsNone(schema.rule_credential_header(rule, credential))
        self.assertEqual(schema.rule_content_modes(rule), (None, ecr.RESPONSE_MODE))
        self.assertEqual(raw["credentials"][0]["injection"], wire.INJECTION)
        self.assertNotIn("credentialHeader", raw["routes"][0])
        compiled = policy_bundle.compile_policy_bundle(raw, verify_signature=False, validate_schema=True)
        self.assertEqual(compiled.routes[0].adapter_type, wire.ADAPTER)
        wire.validate_route(compiled.routes[0])
        self.assertEqual(compiled.routes[0].adapter_config["approval"], wire.APPROVAL)

    def test_scope_and_mandatory_review_are_exact(self):
        for field, value in (("registry_id", "*"), ("region", "cn-north-1"),
                ("repository_name", "../elsewhere"), ("image_tag", ""),
                ("approval_mode", "automatic"), ("upstream_url", "https://other.test")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                inputs.AwsEcrRuleInput(**{**PAYLOAD, field: value})
        missing = dict(PAYLOAD)
        missing.pop("approval_mode")
        with self.assertRaises(ValueError):
            inputs.AwsEcrRuleInput(**missing)
        rule, credential, _ = fixture()
        for change in ({"approval_mode": "automatic"}, {"credential_input": "insert"},
                       {"placeholder": "fake"}, {"methods": ["GET"]}, {"query_keys": ["region"]}):
            with self.subTest(change=change), self.assertRaises(schema.CatalogIntegrityError):
                ecr.validate_rule({**rule, **change}, credential)

    def test_same_client_region_cannot_choose_a_different_repository_or_tag(self):
        rule, _, _ = fixture()
        for change in ({"repository_name": "another/repo"}, {"image_tag": "release-2"}, {"registry_id": "999999999999"}):
            with self.subTest(change=change), self.assertRaises(schema.CatalogConflict):
                ecr.admit_rule({**rule, **change}, {"access_rules": [rule]})
        ecr.admit_rule({**rule, "application_id": "another-client"}, {"access_rules": [rule]})
        changed = {**PAYLOAD, "region": "us-west-2"}
        ecr.admit_rule(ecr.record_fields(inputs.AwsEcrRuleInput(**changed)), {"access_rules": [rule]})

    def test_generic_aws_tuple_and_cross_adapter_signing_remain_refused(self):
        rule, credential, raw = fixture()
        generic = {**rule, "operation_bundle": "not-ecr"}
        with self.assertRaises(schema.CatalogIntegrityError):
            schema.rule_credential_header(generic, credential)
        with self.assertRaises(schema.CatalogIntegrityError):
            schema.rule_request_body_mode(generic, credential)
        for change in ({"type": "bearer", "header": "Authorization"},
                       {"type": "awsEcrSigningV1", "field": "secret_access_key"}):
            candidate = deepcopy(raw)
            candidate["credentials"][0]["injection"] = change
            with self.assertRaises(policy_bundle.PolicyBundleError):
                policy_bundle.compile_policy_bundle(candidate, verify_signature=False, validate_schema=True)
        credential_policy = policy_bundle.CredentialPolicy(id=CREDENTIAL, kind="static", provider="operator-demo",
            provider_subject=SUBJECT, oauth_client_id=None, scopes=(), injection=dict(wire.INJECTION))
        with self.assertRaises(policy_bundle.PolicyBundleError):
            policy_bundle._validate_route_credential_binding("unrelated", "generic.rest", {}, credential_policy, ("/",))
        candidate = deepcopy(raw)
        candidate["credentials"].append({**candidate["credentials"][0], "id": "unused-signing-key", "provider": "unrelated"})
        with self.assertRaises(policy_bundle.PolicyBundleError):
            policy_bundle.compile_policy_bundle(candidate, verify_signature=False, validate_schema=True)

    def test_policy_rejects_extensions_or_mismatched_transport(self):
        _, _, raw = fixture()
        for mutate in (
            lambda route: route.update(credentialHeader={"mode": "replaceExact", "expectedValue": "dummy"}),
            lambda route: route.update(jit={"required": False}),
            lambda route: route["adapter"]["config"].update(approval={"mode": "automatic"}),
            lambda route: route["adapter"]["config"]["request"].update(allowedQueryKeys=["region"]),
            lambda route: route["match"].update(host="api.ecr.us-west-2.amazonaws.com"),
            lambda route: route["constraints"].append({"type": "hostTrustedApproval"}),
        ):
            candidate = deepcopy(raw)
            mutate(candidate["routes"][0])
            with self.assertRaises(policy_bundle.PolicyBundleError):
                policy_bundle.compile_policy_bundle(candidate, verify_signature=False, validate_schema=True)

    def test_capability_requires_live_owner_and_matching_gate(self):
        self.assertTrue(ecr.gate_descriptor_matches(dict(wire.GATE_DESCRIPTOR)))
        self.assertFalse(ecr.gate_descriptor_matches({**wire.GATE_DESCRIPTOR, "extra": "not-matched"}))
        with patch.object(ecr, "_available", return_value=False):
            self.assertIsNone(ecr.capability(PAYLOAD["expected_policy_hash"]))
            with self.assertRaises(schema.CatalogConflict):
                ecr.require_available(PAYLOAD["expected_policy_hash"])
        with patch.object(ecr, "_available", return_value=True):
            capability = ecr.capability(PAYLOAD["expected_policy_hash"])
        self.assertEqual(capability["route_scope"], "one_per_client_region")
        self.assertTrue(capability["publication_approval_required"])


if __name__ == "__main__":
    unittest.main()
