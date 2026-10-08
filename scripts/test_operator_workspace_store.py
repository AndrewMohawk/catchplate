#!/usr/bin/env python3
"""Isolated catalog regression tests with real SQLite, encryption and signing.

Run in a bounded network-none container with read-only source. Only the initial
legacy fixture suppresses the new catalog initializer, reproducing pre-upgrade
data without replacing its credentials, policy, audit or nonce implementation.
No provider, native authority or live deployment is contacted.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import test_operator_demo_persistence as common

ROOT = Path(__file__).resolve().parents[1]
LEGACY_TABLES = (*common._TABLES, "operator_demo_settings",
    "operator_demo_revocations", "operator_demo_nonces")
CATALOG_TABLES = ("operator_catalog_state", "operator_catalog_credentials",
    "operator_catalog_applications", "operator_catalog_rules")


def rows(db, table):
    with closing(db.connect()) as connection:
        return [dict(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")]


def snapshot(db, *, catalog=False):
    with closing(db.connect()) as connection:
        return {table: sorted(tuple(row) for row in connection.execute(f"SELECT * FROM {table}"))
            for table in LEGACY_TABLES + (CATALOG_TABLES if catalog else ())}


def migrate(db, schema):
    with closing(db.connect()) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        schema.initialize(connection)


def catalog(db, schema):
    with closing(db.connect()) as connection:
        schema.validate_bindings(connection)
        return schema.read_catalog(connection)


def legacy_fixture(*, with_revocation=True):
    from serverware import operator_catalog_schema as schema
    with patch.object(schema, "initialize", return_value=None):
        config, db, store, bundles = common.backend()
        first, first_token, digest = common.create_connection(store)
        second, second_token, digest = store.create_connection(store.ConnectionInput(
            name="Legacy header credential", upstream_url="https://api.example.com/v1/other",
            methods=["GET"], auth_type="header", header_name="X-Api-Key",
            secret=common._PROVIDER_SECRET + "-header", response_fields=["status"]), common._ACTOR)
        if with_revocation:
            removed, _, digest = common.create_connection(store)
            store.revoke_connection(store.RevocationInput(connection_id=removed["id"],
                expected_policy_hash=digest), common._ACTOR)
        db.reserve_credential_lease_nonce(common._NONCE_KEY, common._NONCE, now_epoch_ms=common._NOW)
    assert not schema.active()
    return config, db, store, bundles, schema, [first_token, second_token]


def migration_preserves():
    config, db, store, bundles, schema, tokens = legacy_fixture()
    before, policy = snapshot(db), config.POLICY_BUNDLE_PATH.read_bytes()
    high_water = store.get_policy_high_water()
    legacy = [json.loads(row["metadata_json"]) for row in rows(db, "operator_demo_connections")]
    migrate(db, schema)
    assert schema.active()
    current = catalog(db, schema)
    assert current["revision"] == 1
    assert snapshot(db) == before, "migration changed pre-existing authority or history"
    assert config.POLICY_BUNDLE_PATH.read_bytes() == policy
    assert store.get_policy_high_water() == high_water
    assert len(current["credentials"]) == len(current["applications"]) == len(current["access_rules"]) == 2
    for old in legacy:
        credential = next(item for item in current["credentials"] if item["id"] == old["credential_id"])
        application = next(item for item in current["applications"] if item["id"] == old["id"])
        rule = next(item for item in current["access_rules"] if item["id"] == old["id"])
        assert credential["provider_subject"] == old["id"]
        assert application["principal_id"] == old["principal_id"]
        assert application["token_sha256"] == old["token_sha256"]
        assert application["token_expires_at_epoch_ms"] == old["token_expires_at_epoch_ms"]
        assert application["token_version"] == 1
        assert rule["route_id"] == "operator." + old["id"]
        assert rule["application_id"] == old["id"] and rule["credential_id"] == old["credential_id"]
    serialized = json.dumps(current, sort_keys=True)
    assert common._PROVIDER_SECRET not in serialized
    assert all(token not in serialized for token in tokens)
    receipt = json.loads(rows(db, "operator_demo_revocations")[0]["receipt_json"])
    for collection, identifier in (("credentials", receipt["credential_id"]),
            ("applications", receipt["connection_id"]), ("access_rules", receipt["connection_id"])):
        with closing(db.connect()) as connection:
            assert identifier in schema.reserved_identifiers(connection, collection)
            connection.execute("BEGIN IMMEDIATE")
            copied = {**current[collection][0], "id": identifier}
            copied.pop("ordinal")
            try:
                schema.save_resource(connection, collection, copied, create=True)
            except schema.CatalogConflict:
                connection.rollback()
            else:
                raise AssertionError("migration made a retained legacy revoked identifier reusable")
    signed = json.loads(policy)
    compiled = bundles.compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
    assert compiled.hash == high_water["policy_hash"]
    assert bundles.verify_policy_high_water(compiled) == high_water
    committed = snapshot(db, catalog=True)
    migrate(db, schema)
    store.initialize()
    assert catalog(db, schema) == current
    assert snapshot(db, catalog=True) == committed, "repeat initialization changed migrated state"
    assert config.POLICY_BUNDLE_PATH.read_bytes() == policy
    return {"revision": 1, "applications": 2, "legacy_bytes_preserved": True}


def binding_mismatch(*, before_migration):
    config, db, store, bundles, schema, _ = legacy_fixture(with_revocation=False)
    if not before_migration:
        migrate(db, schema)
    original = rows(db, "credentials")[0]
    identifier = original["id"]
    policy = config.POLICY_BUNDLE_PATH.read_bytes()
    mismatches = {
        "name": "unexpected replacement name",
        "kind": "oauth2",
        "lifecycle_status": "revoked",
        "metadata": json.dumps({"provider_id": "operator-demo", "provider_subject": "wrong-account",
            "secret_class": "bearerToken"}),
    }
    for field, value in mismatches.items():
        with closing(db.connect()) as connection, connection:
            connection.execute(f"UPDATE credentials SET {field}=? WHERE id=?", (value, identifier))
        before = snapshot(db, catalog=not before_migration)
        try:
            if before_migration:
                migrate(db, schema)
            else:
                catalog(db, schema)
        except schema.CatalogIntegrityError:
            pass
        else:
            raise AssertionError(f"{field} mismatch retained an active catalog binding")
        assert snapshot(db, catalog=not before_migration) == before
        assert config.POLICY_BUNDLE_PATH.read_bytes() == policy
        if before_migration:
            assert not schema.active(), "failed migration committed its activation marker"
        with closing(db.connect()) as connection, connection:
            connection.execute(f"UPDATE credentials SET {field}=? WHERE id=?", (original[field], identifier))
    if before_migration:
        migrate(db, schema)
    assert len(catalog(db, schema)["credentials"]) == 2
    return {"mismatches_refused": len(mismatches), "before_migration": before_migration}


def legacy_writers_refused():
    config, db, store, bundles, schema, _ = legacy_fixture(with_revocation=False)
    old = json.loads(rows(db, "operator_demo_connections")[0]["metadata_json"])
    migrate(db, schema)
    before, policy = snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    operations = (
        lambda: common.create_connection(store),
        lambda: store.revoke_connection(store.RevocationInput(connection_id=old["id"],
            expected_policy_hash=store.get_policy_high_water()["policy_hash"]), common._ACTOR),
    )
    for operation in operations:
        try:
            operation()
        except schema.LegacyCatalogWriteBlocked:
            pass
        else:
            raise AssertionError("legacy mutation remained available after catalog migration")
        assert snapshot(db, catalog=True) == before
        assert config.POLICY_BUNDLE_PATH.read_bytes() == policy
    return {"legacy_mutations_refused": len(operations)}


def workspace():
    config, db, store, bundles = common.backend()
    from serverware import operator_catalog_schema as schema
    from serverware import operator_catalog_inputs as inputs
    from serverware import operator_catalog_mutations as mutations
    return config, db, store, bundles, schema, inputs, mutations


def review(db, store, schema):
    return {"expected_revision": catalog(db, schema)["revision"],
        "expected_policy_hash": store.get_policy_high_water()["policy_hash"]}


def create_credential(db, store, schema, inputs, mutations, name="Shared provider credential"):
    return mutations.create_credential(inputs.CredentialInput(**review(db, store, schema),
        name=name, auth_type="bearer", secret=common._PROVIDER_SECRET), common._ACTOR)


def create_application(db, store, schema, inputs, mutations, name="Application fixture"):
    return mutations.create_application(inputs.ApplicationInput(**review(db, store, schema),
        name=name, token_lifetime_seconds=3600), common._ACTOR)


def create_rule(db, store, schema, inputs, mutations, application_id, credential_id, name="Access fixture"):
    return mutations.create_rule(inputs.RuleInput(**review(db, store, schema), name=name,
        application_id=application_id, credential_id=credential_id,
        upstream_url="https://api.example.com/v1/items", methods=["GET"],
        response_fields=["status"]), common._ACTOR)


def target(db, store, schema, inputs, identifier):
    return inputs.TargetInput(**review(db, store, schema), id=identifier)


def verify_signed(config, db, store, bundles):
    state = rows(db, "operator_demo_policy")[0]
    raw = state["signed_bundle_json"].encode()
    assert config.POLICY_BUNDLE_PATH.read_bytes() == raw
    signed = json.loads(raw)
    compiled = bundles.compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
    assert compiled.hash == state["policy_hash"]
    assert bundles.verify_policy_high_water(compiled) == store.get_policy_high_water()
    chain = db.verify_audit_chain()
    assert chain["ok"] and chain["complete"]
    return signed


def store_only():
    config, db, store, bundles, schema, inputs, mutations = workspace()
    policy = config.POLICY_BUNDLE_PATH.read_bytes()
    high_water = store.get_policy_high_water()
    credential = create_credential(db, store, schema, inputs, mutations)
    application = create_application(db, store, schema, inputs, mutations)
    assert credential["revision"] == 2 and application["revision"] == 3
    assert "client_token" not in credential
    assert len(application["client_token"]) >= 40
    assert config.POLICY_BUNDLE_PATH.read_bytes() == policy
    assert store.get_policy_high_water() == high_water
    current = catalog(db, schema)
    assert len(current["credentials"]) == len(current["applications"]) == 1
    assert current["access_rules"] == []
    with patch.object(store, "loaded_policy_hash", return_value=None):
        public = mutations.catalog_status()
    serialized = json.dumps(public, sort_keys=True)
    for secret in (common._PROVIDER_SECRET, application["client_token"], current["applications"][0]["token_sha256"]):
        assert secret not in serialized, "status disclosed secret or private token verifier"
    with closing(db.connect()) as connection:
        persisted = "\n".join(connection.iterdump())
    assert common._PROVIDER_SECRET not in persisted and application["client_token"] not in persisted
    common.verify_empty_policy(verify_signed(config, db, store, bundles), rows(db, "operator_demo_policy")[0]["initial_hash"])
    return {"revision": current["revision"], "access_rules": 0}


def shared_lifecycle():
    config, db, store, bundles, schema, inputs, mutations = workspace()
    credential = create_credential(db, store, schema, inputs, mutations)["credential"]
    first = create_application(db, store, schema, inputs, mutations, "First application")["application"]
    second = create_application(db, store, schema, inputs, mutations, "Second application")["application"]
    create_rule(db, store, schema, inputs, mutations, first["id"], credential["id"], "First access")
    create_rule(db, store, schema, inputs, mutations, second["id"], credential["id"], "Second access")
    signed = verify_signed(config, db, store, bundles)
    assert len(signed["credentials"]) == 1 and len(signed["principals"]) == len(signed["routes"]) == 2
    assert {route["credentialRef"] for route in signed["routes"]} == {credential["id"]}
    core = rows(db, "credentials")
    generations = rows(db, "credential_generations")
    preserved = next(item for item in catalog(db, schema)["applications"] if item["id"] == second["id"])
    mutations.revoke_application(target(db, store, schema, inputs, first["id"]), common._ACTOR)
    current = catalog(db, schema)
    assert next(item for item in current["applications"] if item["id"] == second["id"]) == preserved
    assert rows(db, "credentials") == core and rows(db, "credential_generations") == generations
    assert {item["application_id"] for item in current["access_rules"] if item["status"] == "active"} == {second["id"]}
    signed = verify_signed(config, db, store, bundles)
    assert len(signed["credentials"]) == len(signed["routes"]) == len(signed["principals"]) == 1
    assert signed["principals"][0]["id"] == preserved["principal_id"]
    before = snapshot(db, catalog=True)
    try:
        mutations.revoke_credential(target(db, store, schema, inputs, credential["id"]), common._ACTOR)
    except schema.CatalogConflict:
        pass
    else:
        raise AssertionError("credential with active shared assignment was removed")
    assert snapshot(db, catalog=True) == before
    mutations.revoke_application(target(db, store, schema, inputs, second["id"]), common._ACTOR)
    mutations.revoke_credential(target(db, store, schema, inputs, credential["id"]), common._ACTOR)
    current = catalog(db, schema)
    assert len(current["credentials"]) == 1 and current["credentials"][0]["status"] == "revoked"
    assert len(current["access_rules"]) == 2 and all(item["status"] == "revoked" for item in current["access_rules"])
    assert rows(db, "credentials") == [] and rows(db, "credential_generations") == generations
    with closing(db.connect()) as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA foreign_key_list(operator_catalog_credentials)").fetchall() == []
    common.verify_empty_policy(verify_signed(config, db, store, bundles), rows(db, "operator_demo_policy")[0]["initial_hash"])
    before = snapshot(db, catalog=True)
    with closing(db.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            schema.save_resource(connection, "credentials", current["credentials"][0], create=True)
        except schema.CatalogConflict:
            connection.rollback()
        else:
            raise AssertionError("retained revoked catalog identifier was reusable")
    assert snapshot(db, catalog=True) == before
    return {"shared_credential_preserved": True, "revoked_metadata_retained": True}


def rotation():
    config, db, store, bundles, schema, inputs, mutations = workspace()
    credential = create_credential(db, store, schema, inputs, mutations)["credential"]
    original = create_application(db, store, schema, inputs, mutations)
    app_id, old_token = original["application"]["id"], original["client_token"]
    create_rule(db, store, schema, inputs, mutations, app_id, credential["id"])
    old = catalog(db, schema)["applications"][0]
    core = rows(db, "credentials")
    reviewed = inputs.RotateApplicationInput(**review(db, store, schema), id=app_id, token_lifetime_seconds=7200)
    started = time.time_ns() // 1_000_000
    result = mutations.rotate_application_token(reviewed, common._ACTOR)
    ended = time.time_ns() // 1_000_000
    current = catalog(db, schema)["applications"][0]
    assert result["client_token"] != old_token and len(result["client_token"]) >= 40
    assert current["id"] == old["id"] and current["principal_id"] == old["principal_id"]
    assert current["token_sha256"] != old["token_sha256"] and current["token_version"] == old["token_version"] + 1
    assert result["application"]["token_generation"] == current["token_version"]
    assert started + 7_200_000 <= current["token_expires_at_epoch_ms"] <= ended + 7_200_000
    assert rows(db, "credentials") == core, "client rotation changed provider credential"
    signed = verify_signed(config, db, store, bundles)
    assert signed["principals"][0]["proxyAuthorization"]["tokenSha256"] == current["token_sha256"]
    assert old["token_sha256"] not in json.dumps(signed)
    before = snapshot(db, catalog=True)
    try:
        mutations.rotate_application_token(reviewed, common._ACTOR)
    except schema.CatalogConflict:
        pass
    else:
        raise AssertionError("stale rotation replay silently issued another token")
    assert snapshot(db, catalog=True) == before
    with patch.object(store, "loaded_policy_hash", return_value=None):
        public = json.dumps(mutations.catalog_status(), sort_keys=True)
    assert old_token not in public and result["client_token"] not in public
    return {"token_generation": current["token_version"], "finite_expiry": True}


def transaction_failure(stage):
    config, db, store, bundles, schema, inputs, mutations = workspace()
    credential = create_credential(db, store, schema, inputs, mutations)["credential"]
    application = create_application(db, store, schema, inputs, mutations)["application"]
    before, policy = snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    if stage == "stale":
        payload = inputs.RuleInput(**{**review(db, store, schema), "expected_revision": 1}, name="Stale rule",
            application_id=application["id"], credential_id=credential["id"],
            upstream_url="https://api.example.com/v1/items", methods=["GET"], response_fields=["status"])
        try:
            mutations.create_rule(payload, common._ACTOR)
        except schema.CatalogConflict:
            pass
        else:
            raise AssertionError("stale catalog revision was accepted")
    else:
        operation, table = {"policy": ("UPDATE", "operator_demo_policy"),
            "audit": ("INSERT", "audit_events"), "rule": ("INSERT", "operator_catalog_rules")}[stage]
        with closing(db.connect()) as connection, connection:
            connection.execute(f"CREATE TRIGGER catalog_test_abort AFTER {operation} ON {table} "
                "BEGIN SELECT RAISE(ABORT, 'private synthetic workspace write failure'); END")
        try:
            create_rule(db, store, schema, inputs, mutations, application["id"], credential["id"])
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("SQLite write failure did not roll back")
        finally:
            with closing(db.connect()) as connection, connection:
                connection.execute("DROP TRIGGER catalog_test_abort")
    assert snapshot(db, catalog=True) == before
    assert config.POLICY_BUNDLE_PATH.read_bytes() == policy
    create_rule(db, store, schema, inputs, mutations, application["id"], credential["id"])
    assert len(verify_signed(config, db, store, bundles)["routes"]) == 1
    return {"rollback_stage": stage}


def publication_recovery():
    config, db, store, bundles, schema, _ = legacy_fixture(with_revocation=False)
    from serverware import operator_catalog_inputs as inputs
    from serverware import operator_catalog_mutations as mutations
    migrate(db, schema)
    first = catalog(db, schema)["applications"][0]
    old_policy = config.POLICY_BUNDLE_PATH.read_bytes()
    old_legacy = rows(db, "operator_demo_connections")
    replace = os.replace

    def refuse_publication(source, destination, *args, **kwargs):
        if Path(destination) == config.POLICY_BUNDLE_PATH:
            raise OSError("synthetic policy-file publication failure")
        return replace(source, destination, *args, **kwargs)

    with patch.object(os, "replace", refuse_publication):
        result = mutations.revoke_application(target(db, store, schema, inputs, first["id"]), common._ACTOR)
    assert result["application"]["status"] == "revoked" and result["policy"]["activation"] == "pending"
    assert config.POLICY_BUNDLE_PATH.read_bytes() == old_policy
    assert bundles.get_policy_snapshot() is None, "committed revocation left stale signed policy usable"
    committed = snapshot(db, catalog=True)
    assert rows(db, "operator_demo_connections") == old_legacy
    store.initialize()
    assert snapshot(db, catalog=True) == committed, "publication recovery rewrote committed data"
    assert config.POLICY_BUNDLE_PATH.read_bytes() != old_policy
    signed = verify_signed(config, db, store, bundles)
    assert first["principal_id"] not in {item["id"] for item in signed["principals"]}
    assert len(signed["principals"]) == 1
    assert rows(db, "operator_demo_connections") == old_legacy, "recovery modified retained legacy history"
    return {"recovered_from_commit": True, "revoked_application_absent": True}


def expired_application():
    config, db, store, bundles, schema, inputs, mutations = workspace()
    credential = create_credential(db, store, schema, inputs, mutations)["credential"]
    application = create_application(db, store, schema, inputs, mutations)["application"]
    create_rule(db, store, schema, inputs, mutations, application["id"], credential["id"])
    original = catalog(db, schema)["applications"][0]
    core = rows(db, "credentials")
    future = (original["token_expires_at_epoch_ms"] + 1) * 1_000_000
    with patch.object(mutations.time, "time_ns", return_value=future), patch.object(store, "loaded_policy_hash", return_value=None):
        public = mutations.catalog_status()
        assert public["applications"][0]["token_status"] == "expired"
        result = mutations.revoke_application(target(db, store, schema, inputs, application["id"]), common._ACTOR)
    current = catalog(db, schema)["applications"][0]
    assert result["application"]["status"] == "revoked"
    assert current["token_sha256"] == original["token_sha256"]
    assert current["token_expires_at_epoch_ms"] == original["token_expires_at_epoch_ms"]
    assert current["token_version"] == original["token_version"]
    assert rows(db, "credentials") == core
    common.verify_empty_policy(verify_signed(config, db, store, bundles), rows(db, "operator_demo_policy")[0]["initial_hash"])
    return {"expired_application_revoked_without_renewal": True}


def worker(operation):
    operations = {
        "migration": migration_preserves,
        "migration-binding": lambda: binding_mismatch(before_migration=True),
        "active-binding": lambda: binding_mismatch(before_migration=False),
        "legacy-writers": legacy_writers_refused,
        "store-only": store_only,
        "shared-lifecycle": shared_lifecycle,
        "rotation": rotation,
        "publication-recovery": publication_recovery,
        "expired-application": expired_application,
        **{"failure-" + stage: lambda stage=stage: transaction_failure(stage)
            for stage in ("stale", "policy", "audit", "rule")},
    }
    print(json.dumps(operations[operation](), sort_keys=True))


class OperatorWorkspaceStoreTests(unittest.TestCase):
    setUp = common.OperatorDemoPersistenceTests.setUp

    def run_worker(self, operation):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-50:]))
        return json.loads(result.stdout)

    def test_migration_preserves_policy_secrets_tokens_nonces_receipts_and_restart(self):
        self.assertTrue(self.run_worker("migration")["legacy_bytes_preserved"])

    def test_migration_binding_mismatch_rolls_back_activation(self):
        self.assertEqual(self.run_worker("migration-binding")["mismatches_refused"], 4)

    def test_active_catalog_requires_exact_core_credential_binding(self):
        self.assertEqual(self.run_worker("active-binding")["mismatches_refused"], 4)

    def test_legacy_combined_mutations_refuse_after_catalog_activation(self):
        self.assertEqual(self.run_worker("legacy-writers")["legacy_mutations_refused"], 2)

    def test_credential_and_application_storage_grant_no_access(self):
        self.assertEqual(self.run_worker("store-only")["access_rules"], 0)

    def test_shared_credential_application_revocation_and_retained_tombstones(self):
        self.assertTrue(self.run_worker("shared-lifecycle")["shared_credential_preserved"])

    def test_rotation_changes_only_client_token_once_with_finite_expiry(self):
        self.assertEqual(self.run_worker("rotation")["token_generation"], 2)

    def test_stale_revision_does_not_mutate(self):
        self.run_worker("failure-stale")

    def test_policy_write_failure_rolls_back_catalog_and_audit(self):
        self.run_worker("failure-policy")

    def test_audit_write_failure_rolls_back_catalog_and_policy(self):
        self.run_worker("failure-audit")

    def test_rule_write_failure_rolls_back_catalog_and_policy(self):
        self.run_worker("failure-rule")

    def test_postcommit_publication_failure_recovers_without_legacy_resurrection(self):
        self.assertTrue(self.run_worker("publication-recovery")["recovered_from_commit"])

    def test_expired_application_can_be_revoked_without_token_renewal(self):
        self.assertTrue(self.run_worker("expired-application")["expired_application_revoked_without_renewal"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        worker(sys.argv[2])
    else:
        unittest.main(verbosity=2)
