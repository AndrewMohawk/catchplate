#!/usr/bin/env python3
"""Focused per-rule replacement catalog tests; no provider or gate execution.

Run in the pinned backend image with read-only source and network none. Real
SQLite, encryption, signing and policy compilation verify the catalog join;
Rust forwarding behavior and deployment acceptance remain separate evidence.
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
PLACEHOLDER = "Bearer public-catalog-client-placeholder"


def values():
    return {"name": "Exact replacement fixture", "expected_revision": 1,
        "expected_policy_hash": "sha256:" + "0" * 64,
        "application_id": "00000000-0000-4000-8000-000000000001",
        "credential_id": "00000000-0000-4000-8000-000000000002",
        "upstream_url": "https://api.example.com/v1/replacement", "methods": ["GET"],
        "response_fields": ["status"]}


def input_contract():
    from pydantic import ValidationError
    from serverware.operator_catalog_inputs import RuleInput
    base = values()
    assert RuleInput(**base).credential_input == "insert"
    assert RuleInput(**base, credential_input="insert").placeholder is None
    for placeholder in ("x", PLACEHOLDER, "x" * 1024):
        assert RuleInput(**base, credential_input="replace_exact", placeholder=placeholder).placeholder == placeholder
    refused = ({"placeholder": None}, {"placeholder": ""}, {"placeholder": PLACEHOLDER},
        {"credential_input": "insert", "placeholder": None}, {"credential_input": "replace_exact"},
        {"credential_input": "replace_exact", "placeholder": None},
        {"credential_input": "replace_exact", "placeholder": ""},
        {"credential_input": "replace_exact", "placeholder": " leading"},
        {"credential_input": "replace_exact", "placeholder": "trailing "},
        {"credential_input": "replace_exact", "placeholder": "line\nvalue"},
        {"credential_input": "replace_exact", "placeholder": "tab\tvalue"},
        {"credential_input": "replace_exact", "placeholder": "non-ascii-\u00e9"},
        {"credential_input": "replace_exact", "placeholder": "x" * 1025},
        {"credential_input": "replace_exact", "placeholder": 1},
        {"credential_input": "replaceExact", "placeholder": PLACEHOLDER},
        {"credential_input": "replace_exact", "placeholder": PLACEHOLDER, "header_name": "X-Override"})
    for change in refused:
        try:
            RuleInput(**base, **change)
        except ValidationError:
            continue
        raise AssertionError("invalid replacement input admitted")
    return {"accepted": 5, "refused": len(refused)}


def create_rule(db, store, schema, inputs, mutations, application, credential, **overrides):
    payload = {**values(), **workspace.review(db, store, schema),
        "application_id": application["id"], "credential_id": credential["id"], **overrides}
    return mutations.create_rule(inputs.RuleInput(**payload), workspace.common._ACTOR)


def shared_credential_modes():
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    credential = workspace.create_credential(db, store, schema, inputs, mutations)["credential"]
    first = workspace.create_application(db, store, schema, inputs, mutations, "Insertion application")["application"]
    second = workspace.create_application(db, store, schema, inputs, mutations, "Replacement application")["application"]
    core = workspace.rows(db, "credentials")
    generation = workspace.rows(db, "credential_generations")
    insertion = create_rule(db, store, schema, inputs, mutations, first, credential)
    with patch.object(store, "loaded_policy_hash", return_value=None):
        replacement = create_rule(db, store, schema, inputs, mutations, second, credential,
            name="Replacement rule", credential_input="replace_exact", placeholder=PLACEHOLDER,
            response_mode="unfiltered_json", response_fields=[])
    assert insertion["access_rule"]["credential_input"] == "insert"
    assert "placeholder" not in insertion["access_rule"]
    assert replacement["access_rule"]["credential_input"] == "replace_exact"
    assert replacement["access_rule"]["placeholder"] == PLACEHOLDER
    assert replacement["policy"]["activation"] == "pending"
    signed = workspace.verify_signed(config, db, store, bundles)
    assert len(signed["credentials"]) == 1 and len(signed["principals"]) == len(signed["routes"]) == 2
    assert "credentialHeader" not in signed["routes"][0]
    expected = {"mode": "replaceExact", "expectedValue": PLACEHOLDER}
    assert signed["routes"][1]["credentialHeader"] == expected
    assert signed["routes"][1]["adapter"]["config"]["response"]["mode"] == "bufferedPassthrough"
    assert signed["credentials"][0]["injection"] == {"type": "bearer", "header": "Authorization"}
    compiled = bundles.compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
    assert compiled.routes[0].credential_header is None
    assert dict(compiled.routes[1].credential_header) == expected
    assert workspace.rows(db, "credentials") == core
    assert workspace.rows(db, "credential_generations") == generation
    assert PLACEHOLDER not in json.dumps(workspace.rows(db, "audit_events"))
    catalog = workspace.catalog(db, schema)
    assert "placeholder" not in catalog["access_rules"][0]
    for mode, placeholder in (("insert", PLACEHOLDER), ("replace_exact", None), ("other", PLACEHOLDER)):
        invalid = deepcopy(catalog)
        invalid["access_rules"][1].update(credential_input=mode, placeholder=placeholder)
        with closing(db.connect()) as conn:
            try:
                schema.validate_bindings(conn, invalid)
            except schema.CatalogIntegrityError:
                pass
            else:
                raise AssertionError("retained invalid placeholder state accepted")
    with patch.object(store, "loaded_policy_hash", return_value=compiled.hash):
        status = mutations.catalog_status()
    assert status["capabilities"]["credential_input_modes"] == ["insert", "replace_exact"]
    assert status["policy"]["activation"] == "active"
    assert workspace.common._PROVIDER_SECRET not in json.dumps(status)
    return {"one_credential_two_modes": True, "no_secret_copy_or_rotation": True}


def custom_header_and_collision():
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    credential = mutations.create_credential(inputs.CredentialInput(**workspace.review(db, store, schema),
        name="Header credential", auth_type="header", header_name="X-Api-Key",
        secret=workspace.common._PROVIDER_SECRET), workspace.common._ACTOR)["credential"]
    application = workspace.create_application(db, store, schema, inputs, mutations)["application"]
    create_rule(db, store, schema, inputs, mutations, application, credential,
        credential_input="replace_exact", placeholder="public-header-placeholder")
    signed = workspace.verify_signed(config, db, store, bundles)
    assert signed["credentials"][0]["injection"] == {"type": "header", "name": "X-Api-Key", "prefix": ""}
    assert signed["routes"][0]["credentialHeader"] == {"mode": "replaceExact", "expectedValue": "public-header-placeholder"}
    before, raw = workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    for header in ("x-api-key", "x_api_key"):
        try:
            create_rule(db, store, schema, inputs, mutations, application, credential,
                credential_input="replace_exact", placeholder="public-header-placeholder", allowed_headers=[header])
        except bundles.PolicyBundleError:
            pass
        else:
            raise AssertionError("replacement target collides with allowed request header")
        assert workspace.snapshot(db, catalog=True) == before
        assert config.POLICY_BUNDLE_PATH.read_bytes() == raw
    return {"derived_custom_target": True, "alias_conflicts_rolled_back": 2}


def migration_restart():
    config, db, store, bundles, schema, _ = workspace.legacy_fixture(with_revocation=False)
    original_bytes = config.POLICY_BUNDLE_PATH.read_bytes()
    original_state = workspace.snapshot(db)
    workspace.migrate(db, schema)
    original = workspace.catalog(db, schema)
    assert workspace.snapshot(db) == original_state
    assert config.POLICY_BUNDLE_PATH.read_bytes() == original_bytes
    assert all("credential_input" not in rule and "placeholder" not in rule for rule in original["access_rules"])
    from serverware import operator_catalog_inputs as inputs, operator_catalog_mutations as mutations
    create_rule(db, store, schema, inputs, mutations, original["applications"][0], original["credentials"][0],
        credential_input="replace_exact", placeholder=PLACEHOLDER)
    current = workspace.catalog(db, schema)
    assert current["access_rules"][:2] == original["access_rules"]
    assert current["credentials"] == original["credentials"] and current["applications"] == original["applications"]
    signed = workspace.verify_signed(config, db, store, bundles)
    assert signed["routes"][:2] == json.loads(original_bytes)["routes"]
    persisted, policy_bytes = workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    store.initialize()
    assert workspace.snapshot(db, catalog=True) == persisted
    assert config.POLICY_BUNDLE_PATH.read_bytes() == policy_bytes
    with patch.object(store, "loaded_policy_hash", return_value=None):
        status = mutations.catalog_status()
    assert [rule["credential_input"] for rule in status["access_rules"]] == ["insert", "insert", "replace_exact"]
    assert all("placeholder" not in rule for rule in status["access_rules"][:2])
    return {"old_policy_rules_unchanged": 2, "restart_unchanged": True}


def audit_rollback():
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    credential = workspace.create_credential(db, store, schema, inputs, mutations)["credential"]
    application = workspace.create_application(db, store, schema, inputs, mutations)["application"]
    before, raw = workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    with closing(db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER replacement_audit_abort BEFORE INSERT ON audit_events "
            "WHEN NEW.event_type='operator_catalog.access_rule.created' "
            "BEGIN SELECT RAISE(ABORT, 'synthetic replacement audit refusal'); END")
    try:
        create_rule(db, store, schema, inputs, mutations, application, credential,
            credential_input="replace_exact", placeholder=PLACEHOLDER)
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError("replacement policy committed without audit")
    assert workspace.snapshot(db, catalog=True) == before
    assert config.POLICY_BUNDLE_PATH.read_bytes() == raw
    workspace.verify_signed(config, db, store, bundles)
    return {"atomic_replacement_rollback": True}


class OperatorCatalogHeaderReplacementTests(unittest.TestCase):
    setUp = workspace.common.OperatorDemoPersistenceTests.setUp

    def run_worker(self, operation):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-40:]))
        return json.loads(result.stdout)

    def test_strict_placeholder_grammar_and_old_insert_default(self):
        self.assertEqual(self.run_worker("inputs")["refused"], 16)

    def test_same_credential_supports_independent_insert_and_replace_rules(self):
        self.assertTrue(self.run_worker("shared")["one_credential_two_modes"])

    def test_custom_target_derivation_and_request_header_alias_rejection(self):
        self.assertEqual(self.run_worker("custom")["alias_conflicts_rolled_back"], 2)

    def test_migration_and_restart_do_not_broaden_old_insertion_rules(self):
        self.assertTrue(self.run_worker("migration")["restart_unchanged"])

    def test_replacement_rule_policy_and_audit_roll_back_together(self):
        self.assertTrue(self.run_worker("rollback")["atomic_replacement_rollback"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        operations = {"inputs": input_contract, "shared": shared_credential_modes,
            "custom": custom_header_and_collision, "migration": migration_restart, "rollback": audit_rollback}
        print(json.dumps(operations[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
