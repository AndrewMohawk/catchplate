#!/usr/bin/env python3
"""Offline X catalog shape and real policy compiler components.

Synthetic public account records are inputs to these pure joins, NOT consent
evidence or seeded stored credentials. The separate joined lifecycle suite
owns actual account adoption, encrypted state, ASGI and fresh gate admission.
No sockets, subprocesses, provider tokens, database or publication writes.
"""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def no_network(event, _args):
    if event.startswith(("socket.", "subprocess.")):
        raise AssertionError("X catalog component tests forbid network and child processes")


sys.addaudithook(no_network)
from pydantic import ValidationError
from serverware import operator_catalog_x_oauth as account
from serverware import operator_catalog_x_post as post
from serverware import operator_catalog_inputs as inputs
from serverware import operator_catalog_schema as schema
from serverware import operator_catalog_policy as policy
from serverware import operator_x_oauth_profile as profiles
from serverware import x_post

IDS = [str(uuid.UUID(int=value)) for value in range(1, 9)]
STAMP = "2026-10-12T12:00:00+00:00"
HASH = "sha256:" + "a" * 64


def fixture():
    profile = profiles.build_profile(client_id="synthetic-public-x-client", public_origin="https://console.example.com")
    binding = {"schema": "serverware.operatorXAccountBinding/v1", "owner_id": IDS[0],
        "configuration_operation_id": IDS[1], "config_version": 1,
        "profile_binding_digest": profile.binding_digest, "intent_id": IDS[2]}
    metadata = {"oauth": True, "provider": "x.oauth2", "provider_id": "x",
        "oauth_client_id": profile.client_id, "x_app_id": profile.client_id,
        "provider_subject": "123456789", "provider_account": "@Synthetic_User",
        "provider_identity_verified": True, "scopes": list(profiles.SCOPES),
        "refreshable": True, "injection_field": "access_token", "expires_at_epoch_ms": 1_999_999_999_000,
        "operator_x_account": binding}
    core = {"id": IDS[3], "name": "Synthetic X account", "created_at": STAMP,
        "kind": "oauth2", "lifecycle_status": "active", "metadata": metadata}
    record = account.record_fields(core, profile)
    record.update(ordinal=1, version=1)
    configuration = {"owner_id": IDS[0], "operation_id": IDS[1], "config_version": 1,
        "profile_binding_digest": profile.binding_digest, "public_profile": profiles.public_record(profile)}
    return profile, metadata, core, record, configuration


def payload(**changes):
    return {"expected_revision": 1, "expected_policy_hash": HASH, "name": "One text post",
        "application_id": IDS[4], "credential_id": IDS[3], "operation_bundle": "x_text_post_v1", **changes}


def rule():
    value = post.record_fields(inputs.XPostRuleInput(**payload()))
    value.update(id=IDS[5], route_id="operator." + IDS[5], status="active", ordinal=1, version=1, created_at=STAMP)
    return value


class XCatalogComponents(unittest.TestCase):
    def refused(self, function, *args, **kwargs):
        with self.assertRaises(schema.CatalogIntegrityError):
            function(*args, **kwargs)

    def test_exact_account_metadata_and_detached_projection(self):
        profile, metadata, core, record, _ = fixture()
        self.assertEqual(account.validate_record(record, core, profile), metadata)
        generation_projection = {key: core[key] for key in ("id", "kind", "lifecycle_status", "metadata")}
        generation_projection["credential_version"] = 1
        self.assertEqual(account.validate_record(record, generation_projection, profile), metadata)
        self.refused(account.validate_record, record, {**core, "name": "different"}, profile)
        detached = account.validate_account_metadata(metadata, profile)
        detached["scopes"].clear()
        detached["operator_x_account"]["owner_id"] = IDS[7]
        self.assertEqual(metadata["scopes"], list(profiles.SCOPES))
        self.assertEqual(metadata["operator_x_account"]["owner_id"], IDS[0])
        core["metadata"] = json.dumps(metadata)
        self.assertEqual(account.validate_record(record, core, profile), metadata)

    def test_metadata_rejects_secrets_google_markers_and_wrong_types(self):
        profile, metadata, _, _, _ = fixture()
        for key, value in (("access_token", "private-canary"), ("refresh_token", "private-canary"),
                ("oauth_intent_id", IDS[2]), ("oauth_profile_binding_digest", profile.binding_digest),
                ("provider", "google"), ("x_app_id", "other"), ("oauth", 1), ("refreshable", 1),
                ("provider_identity_verified", 1), ("provider_subject", "0123"), ("provider_subject", 123),
                ("provider_account", "plain"), ("scopes", ["tweet.write"]), ("expires_at_epoch_ms", True)):
            with self.subTest(field=key):
                self.refused(account.validate_account_metadata, {**metadata, key: value}, profile)
        for key in metadata:
            self.refused(account.validate_account_metadata, {k: v for k, v in metadata.items() if k != key}, profile)
        self.assertEqual(account.validate_account_metadata({**metadata,
            "refresh_token_expires_at_epoch_ms": 2_000_000_000_000}, profile)["refresh_token_expires_at_epoch_ms"], 2_000_000_000_000)

    def test_association_and_configuration_substitutions_refuse(self):
        profile, metadata, core, record, configuration = fixture()
        account.validate_configuration_binding(record, configuration)
        for key, value in (("owner_id", IDS[7]), ("configuration_operation_id", IDS[7]),
                ("config_version", True), ("config_version", 2), ("profile_binding_digest", HASH)):
            changed = deepcopy(record)
            changed[account.MARKER][key] = value
            self.refused(account.validate_configuration_binding, changed, configuration)
        for key in ("provider_subject", "provider_account", "oauth_client_id", "scopes"):
            changed = deepcopy(core)
            changed["metadata"][key] = [] if key == "scopes" else "other"
            self.refused(account.validate_record, record, changed, profile)
        for value in (None, {}, {**configuration, "operation_id": IDS[7]},
                {**configuration, "public_profile": {**configuration["public_profile"], "client_id": "other"}}):
            self.refused(account.validate_configuration_binding, record, value)
        duplicate = json.dumps(metadata).replace('"oauth": true', '"oauth": false, "oauth": true')
        self.refused(account.validate_record, record, {**core, "metadata": duplicate}, profile)

    def test_lifecycle_shapes_do_not_adopt_or_leak_private_binding(self):
        profile, _, core, record, _ = fixture()
        exposed = account.public_fields(record)
        self.assertEqual(set(exposed), {"connection_type", "provider_id", "provider_account",
            "provider_subject", "oauth_client_id", "scopes", "permission_preset"})
        self.assertNotIn(account.MARKER, exposed)
        quarantine = {**record, "status": "quarantined", "quarantine_work_id": IDS[6],
            "quarantined_at": STAMP, "quarantine_reason": "operator_x_cleanup_fence"}
        account.validate_quarantined_record(quarantine, {**core, "lifecycle_status": "revocation_pending"}, profile)
        self.assertEqual(account.public_fields(quarantine)["provider_revocation_status"], "not_proven")
        self.refused(account.validate_record, quarantine, core, profile)
        self.refused(account.validate_quarantined_record, quarantine, core, profile)
        self.refused(account.validate_identity, {**record, "secret": "private-canary"})
        self.assertTrue(account.selected({account.MARKER: None}))
        self.refused(account.validate_identity, {"auth_type": "bearer", account.MARKER: None})

    def test_post_input_refuses_quota_and_all_caller_selected_wire_fields(self):
        self.assertEqual(inputs.XPostRuleInput(**payload()).operation_bundle, "x_text_post_v1")
        for key, value in (("daily_quota", 1), ("quota", {"max": 1}), ("operation_bundle", "x_username_read_v1"),
                ("upstream_url", "https://api.x.com/2/tweets"), ("methods", ["POST"]),
                ("credential_input", "insert"), ("placeholder", "Bearer private-canary"),
                ("provider_subject", "123"), ("expected_revision", True)):
            with self.subTest(field=key), self.assertRaises(ValidationError):
                inputs.XPostRuleInput(**payload(**{key: value}))

    def test_typed_rule_rejects_app_only_and_generic_crossovers(self):
        _, _, _, record, _ = fixture()
        value = rule()
        post.validate_rule(value, record)
        self.assertIsNone(schema.rule_request_body_mode(value, record))
        self.assertEqual(schema.rule_credential_header(value, record), x_post.REPLACEMENT)
        for changed in ({**record, "auth_type": "bearer", "connection_type": "x_app_bearer_v1"},
                {**record, "auth_type": "google_oauth"}, {**record, "permission_preset": "x_username_read_v1"}):
            self.refused(post.validate_rule, value, changed)
        for changed in ({**value, "operation_bundle": "other"}, {**value, "credential_input": "insert"},
                {**value, "placeholder": "Bearer other"}, {**value, "daily_quota": 20}):
            self.refused(schema.rule_request_body_mode, changed, record)
            self.refused(schema.rule_credential_header, changed, record)

    def test_render_and_actual_compiler_retain_exact_oauth_post_profile(self):
        from serverware import policy_bundle
        _, _, _, record, _ = fixture()
        value = rule()
        application = {"id": IDS[4], "name": "Synthetic client", "status": "active", "ordinal": 1,
            "version": 1, "principal_id": "agent:operator-demo:" + IDS[4],
            "token_sha256": "sha256:" + "b" * 64, "token_expires_at_epoch_ms": 1_999_999_999_000}
        document = policy.render({"credentials": [record], "applications": [application], "access_rules": [value]},
            2, "sha256:" + "c" * 64)
        compiled = policy_bundle.compile_policy_bundle(document, verify_signature=False, validate_schema=True)
        route = compiled.routes[0]
        x_post.validate_route(route)
        self.assertEqual(document["credentials"], [account.credential_policy(record)])
        self.assertEqual(document["routes"][0]["adapter"]["config"]["credentialBinding"], account.route_binding(record))
        self.assertEqual(route.credential_header, {"mode": "replaceExact", "expectedValue": "Bearer serverware-x-post-placeholder-v1"})
        self.assertEqual(route.constraints, (x_post.response_envelope(value["route_id"] + ".envelope"),))
        self.assertFalse(any(row["type"] == "rateLimit" for row in document["routes"][0]["constraints"]))

    def test_same_application_cannot_silently_select_second_account(self):
        first = rule()
        second = {**first, "id": IDS[7], "credential_id": IDS[6]}
        self.refused(post.validate_route_coexistence, [first, second])
        post.validate_route_coexistence([first, {**second, "status": "revoked"}])
        post.validate_route_coexistence([first, {**second, "application_id": IDS[7]}])

    def test_capability_has_no_quota_or_standalone_activation_claim(self):
        capability = account.capability()
        self.assertEqual(capability, {"schema": "serverware.operatorXOAuth/v1",
            "connection_type": "x_user_oauth_v1", "auth_type": "x_oauth", "permission_preset": "x_text_post_v1",
            "start_path": "/api/operator-demo/oauth/x/start",
            "operation_path_prefix": "/api/operator-demo/oauth/x/operations/",
            "disconnect_review_path_template": "/api/operator-demo/oauth/x/accounts/{credential_id}/disconnect-review",
            "disconnect_path": "/api/operator-demo/oauth/x/disconnect", "source_pair_required": True,
            "automatic_refresh": True, "daily_quota_available": False})
        exact = {"schema": "serverware.operatorXPostGate/v1", "adapter": "x.post.v1", "operation": "tweets.write"}
        self.assertTrue(post.gate_descriptor_matches(exact))
        for value in (None, {}, {**exact, "extra": True}, {**exact, "adapter": "x.v2"}):
            self.assertFalse(post.gate_descriptor_matches(value))

    def test_unavailable_or_stale_observation_refuses_before_mutation(self):
        from serverware import operator_x_readiness
        good = {"ready": True, "policy_hash": HASH, "loaded_policy_hash": HASH, "managed_x": {}}
        for value in ({**good, "ready": False}, {**good, "policy_hash": "sha256:" + "b" * 64},
                {**good, "loaded_policy_hash": None}):
            # Failure-only observer seam. No successful admission is asserted.
            with patch.object(operator_x_readiness, "observe", return_value=value), self.assertRaises(schema.CatalogConflict):
                post.require_available(HASH)


if __name__ == "__main__":
    unittest.main(verbosity=2)
