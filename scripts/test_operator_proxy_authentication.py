#!/usr/bin/env python3
"""Real SQLite/signing controls for additive application proxy authentication.

Each group runs in a fresh bounded child with synthetic state. No proxy, native
authority, provider, or stock-client transport is exercised. Only explicit
failure/loaded-observation controls are patched; persistence and signing are real.
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
MODE = "basic_and_bearer_v1"
EVENT = "operator_catalog.application.proxy_authentication_changed"
PATH = "/api/operator-demo/applications/proxy-authentication"
CAPABILITY = {"schema": "serverware.operatorProxyAuthentication/v1",
    "modes": ["bearer", MODE], "path": PATH}


def refused(function, exception):
    try:
        function()
    except exception:
        return
    raise AssertionError("invalid proxy authentication operation was admitted")


class Fixture:
    def __init__(self):
        (self.config, self.db, self.store, self.bundles, self.schema,
            self.inputs, self.mutations) = workspace.workspace()
        self.tokens = []

    def review(self):
        return workspace.review(self.db, self.store, self.schema)

    def application(self, name="Proxy authentication app", **extra):
        result = self.mutations.create_application(self.inputs.ApplicationInput(
            **self.review(), name=name, token_lifetime_seconds=3600, **extra), workspace.common._ACTOR)
        self.tokens.append(result["client_token"])
        return result["application"]

    def credential(self):
        return workspace.create_credential(self.db, self.store, self.schema,
            self.inputs, self.mutations)["credential"]

    def assign(self, application, credential):
        return workspace.create_rule(self.db, self.store, self.schema, self.inputs, self.mutations,
            application["id"], credential["id"])["access_rule"]

    def catalog(self):
        return workspace.catalog(self.db, self.schema)

    def record(self, identifier):
        return next(row for row in self.catalog()["applications"] if row["id"] == identifier)

    def payload(self, identifier, mode=MODE, **changes):
        return self.inputs.ApplicationProxyAuthenticationInput(**{
            **self.review(), "id": identifier, "proxy_authentication": mode, **changes})

    def change(self, identifier, mode=MODE, **changes):
        return self.mutations.set_application_proxy_authentication(
            self.payload(identifier, mode, **changes), workspace.common._ACTOR)

    def snapshot(self):
        return (workspace.snapshot(self.db, catalog=True), self.config.POLICY_BUNDLE_PATH.read_bytes(),
            self.store.get_policy_high_water())

    def signed(self):
        return workspace.verify_signed(self.config, self.db, self.store, self.bundles)

    def privacy(self, result):
        serialized = json.dumps(result, sort_keys=True)
        secrets = [workspace.common._PROVIDER_SECRET, *self.tokens]
        secrets += [row["token_sha256"] for row in self.catalog()["applications"]]
        assert all(value not in serialized for value in secrets), "public result disclosed private material"
        audit = json.dumps(workspace.rows(self.db, "audit_events"))
        assert all(value not in audit for value in secrets), "audit disclosed private material"


def legacy_defaults():
    config, db, store, bundles, schema, _ = workspace.legacy_fixture(with_revocation=False)
    before, policy_bytes = workspace.snapshot(db), config.POLICY_BUNDLE_PATH.read_bytes()
    workspace.migrate(db, schema)
    retained = workspace.catalog(db, schema)
    assert all("proxy_authentication" not in row for row in retained["applications"])
    assert workspace.snapshot(db) == before and config.POLICY_BUNDLE_PATH.read_bytes() == policy_bytes
    from serverware import operator_catalog_inputs as inputs, operator_catalog_mutations as mutations
    for extra in ({}, {"proxy_authentication": "bearer"}):
        result = mutations.create_application(inputs.ApplicationInput(**workspace.review(db, store, schema),
            name="Default transport fixture", token_lifetime_seconds=3600, **extra), workspace.common._ACTOR)
        saved = next(row for row in workspace.catalog(db, schema)["applications"]
            if row["id"] == result["application"]["id"])
        assert result["application"]["proxy_authentication"] == "bearer"
        assert ("proxy_authentication" in saved) == bool(extra)
    assert workspace.catalog(db, schema)["applications"][:2] == retained["applications"]
    committed = workspace.snapshot(db, catalog=True)
    store.initialize()
    assert workspace.snapshot(db, catalog=True) == committed
    assert config.POLICY_BUNDLE_PATH.read_bytes() == policy_bytes
    with patch.object(store, "loaded_policy_hash", return_value=None):
        status = mutations.catalog_status()
    assert status["capabilities"]["application_proxy_authentication"] == CAPABILITY
    assert all(row["proxy_authentication"] == "bearer" for row in status["applications"])
    assert all("basicTransport" not in row["proxyAuthorization"]
        for row in workspace.verify_signed(config, db, store, bundles)["principals"])
    return {"legacy_records_preserved": 2, "reinitialize_unchanged": True}


def assigned_toggle():
    f = Fixture()
    credential = f.credential()
    first, sibling = f.application("Changed app"), f.application("Unaffected app")
    rule, sibling_rule = f.assign(first, credential), f.assign(sibling, credential)
    original_catalog, original_signed = f.catalog(), f.signed()
    core, floors = workspace.rows(f.db, "credentials"), workspace.rows(f.db, "credential_generations")
    for previous, mode in (("bearer", MODE), (MODE, "bearer")):
        before, reviewed = f.record(first["id"]), f.review()
        with patch.object(f.store, "loaded_policy_hash", return_value=reviewed["expected_policy_hash"]):
            result = f.change(first["id"], mode)
        after = f.record(first["id"])
        assert after == {**before, "proxy_authentication": mode, "version": before["version"] + 1}
        assert result["revision"] == reviewed["expected_revision"] + 1
        assert result["policy"]["activation"] == "pending"
        assert result["policy"]["policy_hash"] != reviewed["expected_policy_hash"]
        assert result["affected_rule_ids"] == [rule["id"]] and "client_token" not in result
        current, signed = f.catalog(), f.signed()
        assert current["access_rules"] == original_catalog["access_rules"]
        assert current["credentials"] == original_catalog["credentials"]
        assert f.record(sibling["id"]) == original_catalog["applications"][1]
        assert signed["routes"] == original_signed["routes"]
        assert signed["credentials"] == original_signed["credentials"]
        expected_principals = deepcopy(original_signed["principals"])
        chosen = next(item for item in expected_principals if item["id"] == first["principal_id"])
        if mode == MODE:
            chosen["proxyAuthorization"]["basicTransport"] = {"username": first["id"]}
        assert signed["principals"] == expected_principals
        assert signed["metadata"]["sequence"] == original_signed["metadata"]["sequence"] + (1 if mode == MODE else 2)
        event = json.loads([row for row in workspace.rows(f.db, "audit_events")
            if row["event_type"] == EVENT][-1]["event_json"])
        assert event["previous_proxy_authentication"] == previous and event["proxy_authentication"] == mode
        assert event["affected_rule_ids"] == [rule["id"]] and event["resource_id"] == first["id"]
        assert event["revision"] == result["revision"] and event["token_generation"] == before["token_version"]
        assert event["token_expires_at_epoch_ms"] == before["token_expires_at_epoch_ms"]
        f.privacy(result)
    assert workspace.rows(f.db, "credentials") == core and workspace.rows(f.db, "credential_generations") == floors
    assert sibling_rule["id"] != rule["id"]
    return {"toggles": 2, "shared_assignments_and_tokens_preserved": True}


def unassigned_and_rotation():
    f = Fixture()
    baseline = f.snapshot()[1:]
    first, explicit = f.application(), f.application("Explicit Basic app", proxy_authentication=MODE)
    before = f.record(first["id"])
    result = f.change(first["id"])
    assert f.snapshot()[1:] == baseline and "affected_rule_ids" not in result and "client_token" not in result
    assert f.record(first["id"]) == {**before, "proxy_authentication": MODE, "version": before["version"] + 1}
    assert f.record(explicit["id"])["proxy_authentication"] == MODE
    event = json.loads([row for row in workspace.rows(f.db, "audit_events")
        if row["event_type"] == EVENT][-1]["event_json"])
    assert event["affected_rule_ids"] == []
    old = f.record(first["id"])
    rotated = f.mutations.rotate_application_token(f.inputs.RotateApplicationInput(**f.review(),
        id=first["id"], token_lifetime_seconds=7200), workspace.common._ACTOR)
    assert rotated["client_token"] != f.tokens[0]
    f.tokens.append(rotated["client_token"])
    new = f.record(first["id"])
    assert new["proxy_authentication"] == MODE and new["token_version"] == old["token_version"] + 1
    assert new["token_sha256"] != old["token_sha256"] and f.snapshot()[1:] == baseline
    credential = f.credential()
    f.assign(first, credential)
    signed = f.signed()
    principal = next(row for row in signed["principals"] if row["id"] == first["principal_id"])
    assert principal["proxyAuthorization"] == {"scheme": "Bearer", "tokenId": first["id"],
        "tokenSha256": new["token_sha256"], "expiresAtEpochMs": new["token_expires_at_epoch_ms"],
        "basicTransport": {"username": first["id"]}}
    assert explicit["principal_id"] not in {row["id"] for row in signed["principals"]}
    committed = f.snapshot()
    f.store.initialize()
    assert f.snapshot() == committed
    with patch.object(f.store, "loaded_policy_hash", return_value=None):
        f.privacy(f.mutations.catalog_status())
    return {"unassigned_grants_no_access": True, "rotation_preserves_mode": True}


def refusal_controls():
    f = Fixture()
    app = f.application()
    before = f.snapshot()
    for changes in ({"proxy_authentication": "bearer"}, {"expected_revision": 1},
            {"expected_policy_hash": "sha256:" + "0" * 64}):
        payload = f.inputs.ApplicationProxyAuthenticationInput(**{
            **f.review(), "id": app["id"], "proxy_authentication": MODE, **changes})
        refused(lambda: f.mutations.set_application_proxy_authentication(payload, workspace.common._ACTOR),
            f.schema.CatalogConflict)
        assert f.snapshot() == before
    from pydantic import ValidationError
    valid = {**f.review(), "id": app["id"], "proxy_authentication": MODE}
    for change in ({"proxy_authentication": None}, {"proxy_authentication": "basic"},
            {"proxy_authentication": True}, {"proxy_authentication": 1}, {"extra": "refused"},
            {"expected_revision": True}):
        refused(lambda change=change: f.inputs.ApplicationProxyAuthenticationInput(**{**valid, **change}), ValidationError)
    refused(lambda: f.inputs.ApplicationProxyAuthenticationInput(**f.review(), id=app["id"]), ValidationError)
    for mode in (None, "unknown", True):
        malformed = deepcopy(f.catalog())
        malformed["applications"][0]["proxy_authentication"] = mode
        with closing(f.db.connect()) as conn:
            refused(lambda: f.schema.validate_bindings(conn, malformed), f.schema.CatalogIntegrityError)
    f.mutations.revoke_application(f.inputs.TargetInput(**f.review(), id=app["id"]), workspace.common._ACTOR)
    revoked = f.snapshot()
    refused(lambda: f.change(app["id"]), f.schema.CatalogConflict)
    assert f.snapshot() == revoked
    return {"closed_inputs_and_retained_metadata": True, "revoked_noop_stale_refused": True}


def atomic_failure_and_pending():
    f = Fixture()
    app, credential = f.application(), f.credential()
    f.assign(app, credential)
    before = f.snapshot()
    for operation, table in (("INSERT", "audit_events"), ("UPDATE", "operator_demo_policy")):
        with closing(f.db.connect()) as conn, conn:
            conn.execute(f"CREATE TRIGGER proxy_auth_abort BEFORE {operation} ON {table} "
                "BEGIN SELECT RAISE(ABORT, 'synthetic proxy authentication storage refusal'); END")
        try:
            refused(lambda: f.change(app["id"]), sqlite3.IntegrityError)
            assert f.snapshot() == before, "failed transaction changed authority, revision or audit"
        finally:
            with closing(f.db.connect()) as conn, conn:
                conn.execute("DROP TRIGGER proxy_auth_abort")
    replace = os.replace
    def fail_publication(source, destination, *args, **kwargs):
        if Path(destination) == f.config.POLICY_BUNDLE_PATH:
            raise OSError("synthetic postcommit publication refusal")
        return replace(source, destination, *args, **kwargs)
    with patch.object(os, "replace", fail_publication), patch.object(f.store, "loaded_policy_hash", return_value=None):
        result = f.change(app["id"])
    assert result["policy"]["activation"] == "pending" and "client_token" not in result
    assert f.config.POLICY_BUNDLE_PATH.read_bytes() == before[1]
    assert f.bundles.get_policy_snapshot() is None, "stale policy remained usable after committed change"
    committed = workspace.snapshot(f.db, catalog=True)
    f.store.initialize()
    assert workspace.snapshot(f.db, catalog=True) == committed
    assert f.config.POLICY_BUNDLE_PATH.read_bytes() != before[1]
    assert f.signed()["principals"][0]["proxyAuthorization"]["basicTransport"] == {"username": app["id"]}
    f.privacy(result)
    return {"rolled_back_failure_stages": 2, "pending_commit_recovers": True}


OPERATIONS = {"legacy": legacy_defaults, "assigned": assigned_toggle,
    "unassigned": unassigned_and_rotation, "refusals": refusal_controls,
    "rollback": atomic_failure_and_pending}


class OperatorProxyAuthenticationTests(unittest.TestCase):
    setUp = workspace.common.OperatorDemoPersistenceTests.setUp

    def run_worker(self, operation):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "isolated proxy authentication worker failed; private output withheld")
        return json.loads(result.stdout)

    def test_legacy_defaults_and_reinitialize_preserve_stored_rows_and_signed_bytes(self):
        self.assertTrue(self.run_worker("legacy")["reinitialize_unchanged"])

    def test_assigned_enable_disable_preserve_shared_identity_and_redacted_audit(self):
        self.assertEqual(self.run_worker("assigned")["toggles"], 2)

    def test_unassigned_optin_and_rotation_preserve_mode_without_implicit_access(self):
        self.assertTrue(self.run_worker("unassigned")["rotation_preserves_mode"])

    def test_closed_input_retained_metadata_noop_revoked_and_stale_fail_closed(self):
        self.assertTrue(self.run_worker("refusals")["revoked_noop_stale_refused"])

    def test_policy_and_audit_rollback_and_postcommit_publication_pending(self):
        self.assertEqual(self.run_worker("rollback")["rolled_back_failure_stages"], 2)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
