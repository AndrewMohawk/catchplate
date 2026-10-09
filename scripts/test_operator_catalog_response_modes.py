#!/usr/bin/env python3
"""Focused catalog-to-signed-policy tests for opt-in whole-JSON responses.

Run with read-only source in a bounded network-none container. Uses actual
SQLite/encryption/signing and the merged compiler; no gate or provider runs.
These checks do not establish deployed gate compatibility or proxy transport.
"""
from __future__ import annotations

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

import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]


def rule_values():
    return {"name": "Response mode fixture", "expected_revision": 1,
        "expected_policy_hash": "sha256:" + "0" * 64,
        "application_id": "00000000-0000-4000-8000-000000000001",
        "credential_id": "00000000-0000-4000-8000-000000000002",
        "upstream_url": "https://api.example.com/v1/full", "methods": ["POST"],
        "request_fields": ["message"], "query_keys": ["limit"], "allowed_headers": ["accept"]}


def inputs_contract():
    from pydantic import ValidationError
    from serverware.operator_catalog_inputs import RuleInput
    base = rule_values()
    legacy = RuleInput(**base, response_fields=["status"])
    assert legacy.response_mode == "projected_json"
    for fields in ({}, {"response_fields": []}):
        value = RuleInput(**base, response_mode="unfiltered_json", **fields)
        assert value.response_fields == [] and value.response_mode == "unfiltered_json"
    refused = ({}, {"response_fields": []}, {"response_mode": "projected_json"},
        {"response_mode": "unfiltered_json", "response_fields": ["status"]},
        {"response_mode": "unfiltered_json", "response_fields": None},
        {"response_mode": "bufferedPassthrough"}, {"response_mode": "unfiltered_text"},
        {"response_mode": True}, {"response_mode": "unfiltered_json", "maxBodyBytes": 999999999})
    for values in refused:
        try:
            RuleInput(**base, **values)
        except ValidationError:
            continue
        raise AssertionError("invalid response mode input was admitted")
    return {"accepted": 3, "refused": len(refused)}


def _new_rule(db, store, schema, inputs, mutations, application, credential):
    values = {**rule_values(), **workspace.review(db, store, schema),
        "application_id": application["id"], "credential_id": credential["id"],
        "response_mode": "unfiltered_json"}
    return mutations.create_rule(inputs.RuleInput(**values), workspace.common._ACTOR)


def _profile(route):
    return route["adapter"]["config"]["response"]


def compiled_contract():
    from serverware import operator_catalog_policy as policy
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    credential = workspace.create_credential(db, store, schema, inputs, mutations)["credential"]
    application = workspace.create_application(db, store, schema, inputs, mutations)["application"]
    with patch.object(store, "loaded_policy_hash", return_value=None):
        result = _new_rule(db, store, schema, inputs, mutations, application, credential)
    assert result["policy"]["activation"] == "pending"
    assert result["access_rule"]["response_mode"] == "unfiltered_json"
    assert result["access_rule"]["response_fields"] == []
    signed = workspace.verify_signed(config, db, store, bundles)
    route = signed["routes"][0]
    assert _profile(route) == {
        "mode": "bufferedPassthrough", "bodyFormat": "json", "maxBodyBytes": 1048576,
        "contentTypes": ["application/json"], "allowedHeaders": [], "error": {
            "mode": "bufferedPassthrough", "bodyFormat": "json", "maxBodyBytes": 65536,
            "contentTypes": ["application/json"], "allowedHeaders": [], "onInvalid": "block"}}
    catalog = workspace.catalog(db, schema)
    projected = deepcopy(catalog)
    projected["access_rules"][0].update(response_mode="projected_json", response_fields=["status"])
    state = workspace.rows(db, "operator_demo_policy")[0]
    control = policy.render(projected, state["sequence"], state["initial_hash"])
    compared = deepcopy(route)
    compared["adapter"]["config"]["response"] = _profile(control["routes"][0])
    assert compared == control["routes"][0], "response choice changed request/route constraints"
    for mode, fields in (("unknown", []), ("projected_json", []), ("unfiltered_json", ["status"])):
        invalid = deepcopy(catalog)
        invalid["access_rules"][0].update(response_mode=mode, response_fields=fields)
        with closing(db.connect()) as conn:
            try:
                schema.validate_bindings(conn, invalid)
            except schema.CatalogIntegrityError:
                pass
            else:
                raise AssertionError("saved mode drift was accepted")
        try:
            policy.render(invalid, state["sequence"], state["initial_hash"])
        except schema.CatalogIntegrityError:
            pass
        else:
            raise AssertionError("invalid stored mode was silently rendered")
    with patch.object(store, "loaded_policy_hash", return_value=state["policy_hash"]):
        status = mutations.catalog_status()
    assert status["capabilities"]["response_modes"] == [
        "projected_json", "unfiltered_json", "unfiltered_json_or_empty_v1", "unfiltered_json_or_empty_v2"]
    assert status["capabilities"]["request_body_modes"] == ["preserve_json_v1"]
    assert status["policy"]["activation"] == "active"
    return {"paired_profile": True, "request_unchanged": True, "invalid_stored_modes_refused": 3}


def migration_compatibility():
    config, db, store, bundles, schema, _ = workspace.legacy_fixture(with_revocation=False)
    original_bytes = config.POLICY_BUNDLE_PATH.read_bytes()
    original_state = store.get_policy_high_water()
    workspace.migrate(db, schema)
    original = workspace.catalog(db, schema)
    assert config.POLICY_BUNDLE_PATH.read_bytes() == original_bytes
    assert store.get_policy_high_water() == original_state
    assert all("response_mode" not in rule for rule in original["access_rules"])
    from serverware import operator_catalog_inputs as inputs, operator_catalog_mutations as mutations
    _new_rule(db, store, schema, inputs, mutations, original["applications"][0], original["credentials"][0])
    current = workspace.catalog(db, schema)
    assert current["access_rules"][:2] == original["access_rules"]
    assert current["credentials"] == original["credentials"] and current["applications"] == original["applications"]
    signed = workspace.verify_signed(config, db, store, bundles)
    assert signed["routes"][:2] == json.loads(original_bytes)["routes"]
    assert _profile(signed["routes"][2])["mode"] == "bufferedPassthrough"
    persisted, policy_bytes = workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    store.initialize()
    assert workspace.snapshot(db, catalog=True) == persisted
    assert config.POLICY_BUNDLE_PATH.read_bytes() == policy_bytes
    with patch.object(store, "loaded_policy_hash", return_value=None):
        status = mutations.catalog_status()
    assert [rule["response_mode"] for rule in status["access_rules"]] == ["projected_json", "projected_json", "unfiltered_json"]
    return {"legacy_profiles_preserved": 2, "restart_unchanged": True}


def audit_rollback():
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    credential = workspace.create_credential(db, store, schema, inputs, mutations)["credential"]
    application = workspace.create_application(db, store, schema, inputs, mutations)["application"]
    before, raw = workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    with closing(db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER response_mode_audit_abort BEFORE INSERT ON audit_events "
            "WHEN NEW.event_type='operator_catalog.access_rule.created' "
            "BEGIN SELECT RAISE(ABORT, 'synthetic response-mode audit refusal'); END")
    try:
        _new_rule(db, store, schema, inputs, mutations, application, credential)
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError("new response-mode publication ignored audit failure")
    assert workspace.snapshot(db, catalog=True) == before
    assert config.POLICY_BUNDLE_PATH.read_bytes() == raw
    workspace.verify_signed(config, db, store, bundles)
    return {"atomic_new_mode_rollback": True}


class OperatorCatalogResponseModeTests(unittest.TestCase):
    setUp = workspace.common.OperatorDemoPersistenceTests.setUp

    def run_worker(self, operation):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-40:]))
        return json.loads(result.stdout)

    def test_strict_mode_fields_and_backward_default(self):
        self.assertEqual(self.run_worker("inputs")["refused"], 9)

    def test_paired_compiled_profile_preserves_request_and_rejects_saved_drift(self):
        self.assertTrue(self.run_worker("compiled")["request_unchanged"])

    def test_migrated_projection_and_mixed_rules_survive_restart_unchanged(self):
        self.assertTrue(self.run_worker("migration")["restart_unchanged"])

    def test_new_mode_policy_catalog_audit_rollback_together(self):
        self.assertTrue(self.run_worker("rollback")["atomic_new_mode_rollback"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        operations = {"inputs": inputs_contract, "compiled": compiled_contract,
            "migration": migration_compatibility, "rollback": audit_rollback}
        print(json.dumps(operations[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
