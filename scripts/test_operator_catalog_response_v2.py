#!/usr/bin/env python3
"""Explicit catalog V2 publication; no provider, proxy or native acceptance.

Prepared for bounded network-none execution with read-only source. Each child
uses the existing real SQLite/encryption/signing fixture and merged compiler.
Only the health HTTP transport is synthetic; its bounded reader remains real.
The Google fixture supplies synthetic
already-verified account metadata; it does not prove consent or refresh.
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

import test_operator_catalog_google as google_tests
import test_operator_catalog_response_modes as modes
import test_operator_workspace_store as workspace
from test_operator_catalog_header_replacement import observed_catalog

ROOT = Path(__file__).resolve().parents[1]
MODE = "unfiltered_json_or_empty_v2"
PROFILE = "bufferedJsonOrEmpty204V2"
CAPABILITIES = ["projected_json", "unfiltered_json", "unfiltered_json_or_empty_v1", MODE]


def refused(operation, exception, *, context=None):
    try:
        operation()
    except exception:
        return
    message = "catalog V2 invalid input or state was admitted"
    raise AssertionError(f"{context}: {message}" if context else message)


def profile_contract(route):
    response = route["adapter"]["config"]["response"]
    assert response == {
        "mode": PROFILE, "bodyFormat": "json", "maxBodyBytes": 1048576,
        "contentTypes": ["application/json"], "allowedHeaders": [], "error": {
            "mode": PROFILE, "bodyFormat": "json", "maxBodyBytes": 65536,
            "contentTypes": ["application/json"], "allowedHeaders": [], "onInvalid": "block"}}
    envelopes = [item for item in route["constraints"] if item["type"] == "responseEnvelope"]
    assert envelopes
    for envelope in envelopes:
        assert envelope["bodyPresence"] == "jsonOrEmpty204V1"
        assert envelope["unlistedHeaderPolicy"] == "discardUnselectedV1"
        assert envelope["contentTypes"] == ["application/json"]
        assert 204 in envelope["statusCodes"]
        assert envelope["allowedResponseHeaderNames"] == []
        assert envelope["responseHeaderRules"] == []


def create_rule(db, store, schema, inputs, mutations, application, credential, *, mode=MODE):
    values = {**modes.rule_values(), **workspace.review(db, store, schema),
        "application_id": application["id"], "credential_id": credential["id"],
        "upstream_url": "https://api.example.com/v1/full-" + mode,
        "response_mode": mode, "response_fields": []}
    with patch.object(store, "loaded_gate_status",
            side_effect=AssertionError("mutation attempted optional gate observation")) as observation:
        result = mutations.create_rule(inputs.RuleInput(**values), workspace.common._ACTOR)
    observation.assert_not_called()
    return result


def input_contract():
    from pydantic import ValidationError
    from catchplate.operator_catalog_inputs import RuleInput
    base = modes.rule_values()
    for fields in ({}, {"response_fields": []}):
        model = RuleInput(**base, response_mode=MODE, **fields)
        assert model.response_mode == MODE and model.response_fields == []
    legacy = RuleInput(**base, response_fields=["status"])
    assert legacy.response_mode == "projected_json"
    for mode in CAPABILITIES[1:-1]:
        assert RuleInput(**base, response_mode=mode).response_mode == mode
    invalid = ({"response_fields": ["status"]}, {"response_fields": None},
        {"response_mode": "bufferedJsonOrEmpty204V2"}, {"response_mode": None},
        {"response_mode": True}, {"unlistedHeaderPolicy": "discardUnselectedV1"},
        {"allowedResponseHeaderNames": ["server"]}, {"response_headers": ["server"]})
    for change in invalid:
        refused(lambda: RuleInput(**{**base, "response_mode": MODE, **change}), ValidationError)
    return {"input_refusals": len(invalid), "old_default_unchanged": True}


def persisted_profile():
    from catchplate import operator_catalog_policy as policy
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    credential = workspace.create_credential(db, store, schema, inputs, mutations)["credential"]
    application = workspace.create_application(db, store, schema, inputs, mutations)["application"]
    result = create_rule(db, store, schema, inputs, mutations, application, credential)
    assert result["access_rule"]["response_mode"] == MODE
    assert result["access_rule"]["response_fields"] == []
    assert result["policy"]["activation"] == "pending"
    signed = workspace.verify_signed(config, db, store, bundles)
    route = signed["routes"][0]
    profile_contract(route)
    catalog = workspace.catalog(db, schema)
    assert catalog["access_rules"][0]["response_mode"] == MODE
    state = workspace.rows(db, "operator_demo_policy")[0]
    previous = deepcopy(catalog)
    previous["access_rules"][0]["response_mode"] = "unfiltered_json_or_empty_v1"
    old_route = policy.render(previous, state["sequence"], state["initial_hash"])["routes"][0]
    # Only the selected response version and envelope discard policy differ.
    restored = deepcopy(route)
    restored["adapter"]["config"]["response"]["mode"] = "bufferedJsonOrEmpty204V1"
    restored["adapter"]["config"]["response"]["error"]["mode"] = "bufferedJsonOrEmpty204V1"
    for envelope in restored["constraints"]:
        if envelope["type"] == "responseEnvelope":
            del envelope["unlistedHeaderPolicy"]
    assert restored == old_route
    before, raw = workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    for change in ({"response_fields": ["status"]}, {"response_mode": None},
            {"response_mode": "bufferedJsonOrEmpty204V2"}):
        invalid = deepcopy(catalog)
        invalid["access_rules"][0].update(change)
        with closing(db.connect()) as conn:
            refused(lambda: schema.validate_bindings(conn, invalid), schema.CatalogIntegrityError)
        refused(lambda: policy.render(invalid, state["sequence"], state["initial_hash"]),
            schema.CatalogIntegrityError)
    wrong_hash = state["policy_hash"][:-1] + ("0" if state["policy_hash"][-1] != "0" else "1")
    for digest in (None, wrong_hash):
        pending = observed_catalog(config, store, mutations, digest)
        assert pending["policy"]["activation"] == "pending"
        assert pending["policy"]["loaded_policy_hash"] == digest
        assert pending["access_rules"][0]["enforcement"] == "pending"
        assert pending["access_rules"][0]["response_mode"] == MODE
    status = observed_catalog(config, store, mutations, state["policy_hash"])
    assert status["capabilities"]["response_modes"] == CAPABILITIES
    assert status["capabilities"]["request_body_modes"] == ["preserve_json_v1"]
    assert status["access_rules"][0]["response_mode"] == MODE
    assert status["policy"]["activation"] == "active"
    assert status["policy"]["loaded_policy_hash"] == state["policy_hash"]
    assert status["access_rules"][0]["enforcement"] == "active"
    assert workspace.snapshot(db, catalog=True) == before
    assert config.POLICY_BUNDLE_PATH.read_bytes() == raw
    store.initialize()
    assert workspace.snapshot(db, catalog=True) == before
    assert config.POLICY_BUNDLE_PATH.read_bytes() == raw
    return {"paired_profile": True, "no_output_headers": True, "restart_unchanged": True,
        "fresh_health_observations": 3, "pending_health_controls": 2}


def old_retention():
    config, db, store, bundles, schema, _ = workspace.legacy_fixture(with_revocation=False)
    original_bytes = config.POLICY_BUNDLE_PATH.read_bytes()
    original_hash = store.get_policy_high_water()
    workspace.migrate(db, schema)
    assert config.POLICY_BUNDLE_PATH.read_bytes() == original_bytes
    assert store.get_policy_high_water() == original_hash
    from catchplate import operator_catalog_inputs as inputs, operator_catalog_mutations as mutations
    old = workspace.catalog(db, schema)
    assert all("response_mode" not in rule for rule in old["access_rules"])
    application, credential = old["applications"][0], old["credentials"][0]
    for mode in ("unfiltered_json", "unfiltered_json_or_empty_v1"):
        create_rule(db, store, schema, inputs, mutations, application, credential, mode=mode)
    before = workspace.catalog(db, schema)
    old_records = workspace.rows(db, "operator_catalog_rules")
    old_signed = workspace.verify_signed(config, db, store, bundles)
    old_policy = config.POLICY_BUNDLE_PATH.read_bytes()
    old_high_water = store.get_policy_high_water()
    store.initialize()
    assert config.POLICY_BUNDLE_PATH.read_bytes() == old_policy
    assert store.get_policy_high_water() == old_high_water
    assert workspace.rows(db, "operator_catalog_rules") == old_records
    create_rule(db, store, schema, inputs, mutations, application, credential)
    current = workspace.catalog(db, schema)
    signed = workspace.verify_signed(config, db, store, bundles)
    assert current["access_rules"][:-1] == before["access_rules"]
    assert workspace.rows(db, "operator_catalog_rules")[:-1] == old_records
    assert current["credentials"] == before["credentials"]
    assert current["applications"] == before["applications"]
    assert signed["routes"][:-1] == old_signed["routes"]
    assert signed["routes"][:2] == json.loads(original_bytes)["routes"]
    assert signed["credentials"] == old_signed["credentials"]
    assert signed["principals"] == old_signed["principals"]
    profile_contract(signed["routes"][-1])
    for route in signed["routes"][:-1]:
        assert all("unlistedHeaderPolicy" not in item for item in route["constraints"])
    return {"old_records_and_routes_preserved": 4, "old_hash_unchanged_on_restart": True}


def atomic_rollback():
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    credential = workspace.create_credential(db, store, schema, inputs, mutations)["credential"]
    application = workspace.create_application(db, store, schema, inputs, mutations)["application"]
    before, raw = workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    with closing(db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER response_v2_audit_abort BEFORE INSERT ON audit_events "
            "WHEN NEW.event_type='operator_catalog.access_rule.created' "
            "BEGIN SELECT RAISE(ABORT, 'synthetic V2 audit refusal'); END")
    refused(lambda: create_rule(db, store, schema, inputs, mutations, application, credential),
        sqlite3.IntegrityError)
    assert workspace.snapshot(db, catalog=True) == before
    assert config.POLICY_BUNDLE_PATH.read_bytes() == raw
    workspace.verify_signed(config, db, store, bundles)
    return {"atomic_rollback": True}


def google_admission():
    f = google_tests.Fixture()
    application = f.application()
    f.rule(application, "profile")
    old = workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    result = f.rule(application, response_mode=MODE, response_fields=[])
    assert result["access_rule"]["response_mode"] == MODE
    signed = workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    assert signed["routes"][0] == old["routes"][0]
    assert signed["credentials"] == old["credentials"]
    assert signed["principals"] == old["principals"]
    route = signed["routes"][1]
    profile_contract(route)
    assert route["match"]["host"] == "gmail.googleapis.com"
    assert route["match"]["methods"] == ["GET"]
    assert route["match"]["paths"] == ["/gmail/v1/users/me/messages"]
    request = route["adapter"]["config"]["request"]
    assert request["bodyMode"] == "none" and request["maxBodyBytes"] == 0
    assert route["adapter"]["config"]["credentialBinding"] == f.google.route_binding(f.record)
    assert signed["credentials"][0]["scopes"] == list(f.profile.scopes)

    # A single ID-shaped segment named "send" is still a GET read route. It
    # does not authorize Gmail's POST send operation or deeper resource paths.
    f.rule(application, "messages/send", response_mode=MODE, response_fields=[])
    with_message_id = workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    assert with_message_id["routes"][:-1] == signed["routes"]
    assert with_message_id["credentials"] == signed["credentials"]
    assert with_message_id["principals"] == signed["principals"]
    message_id_route = with_message_id["routes"][-1]
    profile_contract(message_id_route)
    assert message_id_route["match"]["host"] == "gmail.googleapis.com"
    assert message_id_route["match"]["methods"] == ["GET"]
    assert message_id_route["match"]["paths"] == ["/gmail/v1/users/me/messages/send"]
    message_id_request = message_id_route["adapter"]["config"]["request"]
    assert message_id_request["bodyMode"] == "none" and message_id_request["maxBodyBytes"] == 0
    assert message_id_route["adapter"]["config"]["credentialBinding"] == f.google.route_binding(f.record)

    before = f.snapshot()
    invalid = (("POST method", {"methods": ["POST"]}),
        ("mixed GET/POST methods", {"methods": ["GET", "POST"]}),
        ("request fields", {"request_fields": ["raw"]}),
        ("preserved request body", {"request_body_mode": "preserve_json_v1"}),
        ("other provider origin", {"upstream_url": "https://api.example.com/v1/items"}),
        ("unsupported nested path", {"upstream_url": google_tests.GMAIL + "messages/id/attachments/part"}))
    for index, (label, change) in enumerate(invalid, start=1):
        context = f"Google refusal case {index}/{len(invalid)} ({label})"
        refused(lambda: f.rule(application, **{"response_mode": MODE, "response_fields": [], **change}),
            (f.schema.CatalogIntegrityError, ValueError), context=context)
        assert f.snapshot() == before, f"{context}: refused mutation changed retained state"
    with closing(f.db.connect()) as conn:
        f.schema.validate_bindings(conn)
    return {"gmail_get_no_body_v2": True, "unchanged_google_refusals": len(invalid)}


OPERATIONS = {"inputs": input_contract, "persisted": persisted_profile,
    "retention": old_retention, "rollback": atomic_rollback, "google": google_admission}


def worker(test, operation):
    result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
        cwd=ROOT, env=test.environment, capture_output=True, text=True, timeout=90)
    test.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-40:]))
    return json.loads(result.stdout)


class OperatorCatalogResponseV2Tests(unittest.TestCase):
    setUp = workspace.common.OperatorDemoPersistenceTests.setUp

    def test_explicit_v2_input_and_unchanged_old_defaults(self):
        self.assertEqual(worker(self, "inputs")["input_refusals"], 8)

    def test_v2_signed_persistence_capability_and_no_output_headers(self):
        self.assertTrue(worker(self, "persisted")["restart_unchanged"])

    def test_all_old_modes_records_routes_and_restart_hashes_retained(self):
        self.assertEqual(worker(self, "retention")["old_records_and_routes_preserved"], 4)

    def test_v2_catalog_policy_and_audit_rollback_together(self):
        self.assertTrue(worker(self, "rollback")["atomic_rollback"])


class OperatorGoogleResponseV2Tests(unittest.TestCase):
    setUp = google_tests.OperatorCatalogGoogleTests.setUp

    def test_google_v2_get_no_body_does_not_broaden_operation_provider_or_scopes(self):
        self.assertEqual(worker(self, "google")["unchanged_google_refusals"], 6)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
