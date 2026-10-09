#!/usr/bin/env python3
"""Static-key replacement transaction tests, not proxy/cache propagation proof.

Run in the bounded network-none application image with read-only source and a
private TMPDIR. Each child cold-admits the operator profile and uses real SQLite,
envelope encryption, signatures and publication ownership. Only gate health
observation is stubbed. Explicit negative/fault controls never grant authority.
No app server, provider, Rust gate or native authority is started.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import traceback
import unittest
from unittest.mock import patch
import uuid

import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
OLD = workspace.common._PROVIDER_SECRET
NEW = "synthetic-static-key-replacement-next-value"
OTHER = "synthetic-static-key-replacement-competing-value"
EVENT = "operator_catalog.credential.key_replaced"


def refused(call, exception):
    try:
        call()
    except exception:
        return
    raise AssertionError("replacement unexpectedly admitted a refused operation")


class Fixture:
    def __init__(self, *, header=False, shared=False):
        (self.config, self.db, self.store, self.bundles, self.schema,
            self.inputs, self.mutations) = workspace.workspace()
        self.created = self.mutations.create_credential(self.inputs.CredentialInput(
            **self.review(), name="Retained provider key", auth_type="header" if header else "bearer",
            header_name="X-Api-Key" if header else None, secret=OLD), workspace.common._ACTOR)
        self.identifier = self.created["credential"]["id"]
        self.tokens = []
        if shared:
            for index in range(2):
                app = workspace.create_application(self.db, self.store, self.schema,
                    self.inputs, self.mutations, f"Shared key application {index}")
                self.tokens.append(app["client_token"])
                self.mutations.create_rule(self.inputs.RuleInput(**self.review(),
                    name=f"Retained rule {index}", application_id=app["application"]["id"],
                    credential_id=self.identifier, upstream_url="https://api.example.com/v1/items",
                    methods=["GET"], response_fields=["status"],
                    **({"credential_input": "replace_exact", "placeholder": "public-dummy"}
                       if index else {})), workspace.common._ACTOR)

    def review(self):
        return workspace.review(self.db, self.store, self.schema)

    def core(self, conn=None):
        if conn is None:
            with closing(self.db.connect()) as current:
                return self.core(current)
        return dict(conn.execute("SELECT * FROM credentials WHERE id=?", (self.identifier,)).fetchone())

    def catalog(self):
        return workspace.catalog(self.db, self.schema)

    def snapshot(self):
        return (workspace.snapshot(self.db, catalog=True),
            self.config.POLICY_BUNDLE_PATH.read_bytes(), self.store.get_policy_high_water())

    def payload(self, **changes):
        return self.inputs.ReplaceCredentialKeyInput(**{**self.review(), "id": self.identifier,
            "expected_credential_generation": self.core()["credential_version"], "secret": NEW, **changes})

    def replace(self, payload=None):
        return self.mutations.replace_credential_key(payload or self.payload(), workspace.common._ACTOR)

    def verify_secret(self, expected):
        # Deliberately no assertion formatter includes either secret value.
        credential = self.db.get_credential(self.identifier, include_secret=True)
        assert credential is not None and credential["secret"] == expected, "encrypted replacement differs"

    def verify_privacy(self, receipt):
        public = self.mutations.catalog_status()
        with closing(self.db.connect()) as conn:
            persisted = "\n".join(conn.iterdump()).encode()
        buffers = [persisted, json.dumps(public).encode(), json.dumps(receipt).encode(),
            self.config.POLICY_BUNDLE_PATH.read_bytes(), json.dumps(workspace.rows(self.db, "audit_events")).encode()]
        for path in (self.config.DB_PATH, Path(str(self.config.DB_PATH) + "-wal")):
            if path.exists():
                buffers.append(path.read_bytes())
        assert not any(secret.encode() in value for secret in (OLD, NEW, OTHER, *self.tokens)
            for value in buffers), "plaintext key or application token leaked"


def successful(*, header=False, identical=False, shared=False):
    f = Fixture(header=header, shared=shared)
    from serverware import runtime
    before, core, catalog = f.snapshot(), f.core(), f.catalog()
    previous = core["credential_version"]
    expected = OLD if identical else NEW
    real_helper = f.db.replace_operator_static_credential_secret_if_version
    real_invalidate = runtime.invalidate_secret_leases
    helper_connections, evictions = [], []
    target_cache_key, unrelated_cache_key = (f.identifier, "synthetic"), (str(uuid.uuid4()), "synthetic")
    # Opaque sentinels exercise the real local eviction function only. They are
    # not issued leases and make no claim about another process or in-flight I/O.
    with runtime._credential_lock:
        runtime._credential_cache[target_cache_key] = object()
        runtime._credential_cache[unrelated_cache_key] = object()

    def observed_helper(conn, identifier, **kwargs):
        assert type(conn) is sqlite3.Connection and conn.in_transaction
        f.store.operator_publication.assert_held()
        helper_connections.append(conn)
        return real_helper(conn, identifier, **kwargs)

    def observed_invalidation(identifier):
        assert identifier == f.identifier and len(helper_connections) == 1
        refused(f.store.operator_publication.assert_held, f.store.operator_publication.PublicationError)
        assert not helper_connections[0].in_transaction
        # A separate writer can enter only after the caller transaction ended.
        with closing(f.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            assert f.core(conn)["credential_version"] == previous + 1
            conn.rollback()
        real_invalidate(identifier)
        evictions.append(identifier)

    # No decrypt/equality oracle is permitted inside an accepted replacement.
    with patch.object(f.db, "replace_operator_static_credential_secret_if_version", side_effect=observed_helper), \
            patch.object(f.db, "decrypt_secret_envelope", side_effect=AssertionError("old key decryption attempted")), \
            patch.object(runtime, "invalidate_secret_leases", side_effect=observed_invalidation):
        result = f.replace(f.payload(secret=expected))
    assert len(helper_connections) == 1 and evictions == [f.identifier]
    with runtime._credential_lock:
        assert target_cache_key not in runtime._credential_cache and unrelated_cache_key in runtime._credential_cache
        runtime._credential_cache.pop(unrelated_cache_key)
    after, current, retained = f.snapshot(), f.core(), f.catalog()
    assert current["credential_version"] == previous + 1
    for key in ("id", "name", "kind", "metadata", "created_at", "lifecycle_status"):
        assert current[key] == core[key], "replacement changed credential identity"
    assert current["secret_ciphertext"] != core["secret_ciphertext"] and current["secret_nonce"] != core["secret_nonce"]
    assert all(current[key] for key in ("encrypted_dek", "secret_ciphertext", "secret_nonce", "secret_kek_id"))
    assert retained["revision"] == catalog["revision"] + 1
    assert retained["applications"] == catalog["applications"] and retained["access_rules"] == catalog["access_rules"]
    old_record, new_record = catalog["credentials"][0], retained["credentials"][0]
    assert new_record["version"] == old_record["version"] + 1
    assert {k: v for k, v in new_record.items() if k not in {"version", "key_replaced_at"}} == \
        {k: v for k, v in old_record.items() if k not in {"version", "key_replaced_at"}}
    assert after[1:] == before[1:], "replacement changed policy bytes or high water"
    assert after[0]["operator_demo_policy"] == before[0]["operator_demo_policy"]
    assert len(after[0]["audit_events"]) == len(before[0]["audit_events"]) + 1
    floor = next(row for row in workspace.rows(f.db, "credential_generations") if row["credential_id"] == f.identifier)
    assert floor["last_version"] == previous + 1
    assert result["credential"]["id"] == f.identifier
    assert result["credential"]["credential_generation"] == previous + 1
    assert result["key_replacement"] == {"previous_credential_generation": previous,
        "credential_generation": previous + 1, "cache_invalidation": "local_completed",
        "in_flight_requests": "not_recalled"}
    events = [row for row in workspace.rows(f.db, "audit_events") if row["event_type"] == EVENT]
    assert len(events) == 1
    event = json.loads(events[0]["event_json"])
    assert event["resource_id"] == f.identifier and event["previous_credential_generation"] == previous
    assert event["credential_generation"] == previous + 1 and event["revision"] == result["revision"]
    f.verify_secret(expected)
    f.verify_privacy(result)
    workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    return {"generation": previous + 1, "same_connection": True, "identity_and_policy_preserved": True}


def stale_reviews():
    f = Fixture()
    stale = f.payload()
    workspace.create_application(f.db, f.store, f.schema, f.inputs, f.mutations)
    before = f.snapshot()
    refused(lambda: f.replace(stale), f.schema.CatalogConflict)
    assert f.snapshot() == before
    for changes in ({"expected_policy_hash": "sha256:" + "0" * 64},
            {"expected_credential_generation": f.core()["credential_version"] + 1}):
        refused(lambda: f.replace(f.payload(**changes)), f.schema.CatalogConflict)
        assert f.snapshot() == before
    # Advance only core generation through the real storage API. Catalog/policy
    # CAS still match, so this checks the independent credential-generation CAS.
    stale_core = f.payload()
    with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        f.db.update_credential(f.identifier, {"secret": OTHER}, _connection=conn)
    before = f.snapshot()
    refused(lambda: f.replace(stale_core), f.schema.CatalogConflict)
    assert f.snapshot() == before
    f.verify_secret(OTHER)
    public = next(row for row in f.mutations.catalog_status()["credentials"] if row["id"] == f.identifier)
    assert public["credential_generation"] == 2 and public["version"] == 1
    return {"independent_cas_refusals": 4}


def missing_and_revoked():
    f = Fixture()
    before = f.snapshot()
    refused(lambda: f.replace(f.payload(id=str(uuid.uuid4()))), f.mutations.CatalogNotFound)
    assert f.snapshot() == before
    f.mutations.revoke_credential(workspace.target(f.db, f.store, f.schema, f.inputs, f.identifier), workspace.common._ACTOR)
    before = f.snapshot()
    payload = f.inputs.ReplaceCredentialKeyInput(**f.review(), id=f.identifier,
        expected_credential_generation=1, secret=NEW)
    refused(lambda: f.replace(payload), f.schema.CatalogConflict)
    assert f.snapshot() == before
    assert f.mutations.catalog_status()["credentials"][0]["credential_generation"] is None
    return {"missing_and_revoked_refused": True}


def google_refused():
    import test_operator_catalog_google as google
    f = google.Fixture()
    before = f.snapshot()
    payload = f.inputs.ReplaceCredentialKeyInput(**workspace.review(f.db, f.store, f.schema),
        id=f.record["id"], expected_credential_generation=f.core()["credential_version"], secret=NEW)
    refused(lambda: f.mutations.replace_credential_key(payload, workspace.common._ACTOR), f.schema.CatalogConflict)
    assert f.snapshot() == before
    assert "credential_generation" not in f.mutations.catalog_status()["credentials"][0]
    return {"verified_synthetic_google_account_refused": True}


def audit_rollback():
    f = Fixture(shared=True)
    with closing(f.db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER key_replacement_audit_abort BEFORE INSERT ON audit_events "
            "WHEN NEW.event_type='operator_catalog.credential.key_replaced' "
            "BEGIN SELECT RAISE(ABORT,'synthetic key replacement audit refusal'); END")
    before = f.snapshot()
    from serverware import runtime
    with patch.object(runtime, "invalidate_secret_leases", side_effect=AssertionError("precommit cache eviction")) as eviction:
        refused(f.replace, sqlite3.IntegrityError)
    assert eviction.call_count == 0 and f.snapshot() == before
    f.verify_secret(OLD)
    workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    return {"cipher_generation_catalog_audit_and_policy_rolled_back": True}


def concurrent_single_winner():
    f = Fixture()
    payload = f.payload().model_dump()
    before, initial = f.snapshot(), f.core()["credential_version"]
    barrier = threading.Barrier(2, timeout=5)

    def replace_once(secret):
        candidate = f.inputs.ReplaceCredentialKeyInput(**{**payload, "secret": secret})
        barrier.wait()
        try:
            return "committed", secret, f.replace(candidate)
        except f.schema.CatalogConflict:
            return "conflict", None, None

    # Child timeout is the final bound even if a broken lock prevents shutdown.
    # Exactly two calls; a conflicted or uncertain mutation is never retried.
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(replace_once, secret) for secret in (NEW, OTHER)]
        results = [future.result(timeout=20) for future in futures]
    assert sorted(item[0] for item in results) == ["committed", "conflict"]
    winner = next(item for item in results if item[0] == "committed")
    f.verify_secret(winner[1])
    assert f.core()["credential_version"] == initial + 1
    after = f.snapshot()
    assert after[1:] == before[1:] and f.catalog()["revision"] == payload["expected_revision"] + 1
    assert len(after[0]["audit_events"]) == len(before[0]["audit_events"]) + 1
    assert len([row for row in workspace.rows(f.db, "audit_events") if row["event_type"] == EVENT]) == 1
    f.verify_privacy(winner[2])
    workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    return {"calls": 2, "committed": 1, "conflicts": 1}


def helper_ownership():
    f = Fixture()
    from serverware import operator_demo
    helper, publication = f.db.replace_operator_static_credential_secret_if_version, f.store.operator_publication
    before = f.snapshot()
    arguments = {"expected_version": 1, "secret": NEW}
    with closing(f.db.connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        refused(lambda: helper(conn, f.identifier, **arguments), publication.PublicationError)
        conn.rollback()
        with publication.exclusive():
            refused(lambda: helper(conn, f.identifier, **arguments), f.db.MetadataStoreError)
            conn.execute("BEGIN IMMEDIATE")
            # Negative-only profile fault: no native path or authority is used.
            with patch.object(operator_demo, "active", return_value=False):
                refused(lambda: helper(conn, f.identifier, **arguments), f.db.MetadataStoreError)
            conn.rollback()
            refused(lambda: helper(object(), f.identifier, **arguments), f.db.MetadataStoreError)
            with closing(sqlite3.connect(":memory:")) as foreign:
                foreign.execute("BEGIN")
                refused(lambda: helper(foreign, f.identifier, **arguments), f.db.MetadataStoreError)
    assert f.snapshot() == before
    return {"ownership_transaction_profile_and_store_refusals": 5}


def helper_integrity():
    f = Fixture()
    helper = f.db.replace_operator_static_credential_secret_if_version
    before = f.snapshot()
    core = f.core()
    oauth_metadata = {**json.loads(core["metadata"]), "oauth": True}
    mutations = (
        ("UPDATE credentials SET metadata=? WHERE id=?", (json.dumps(oauth_metadata), f.identifier)),
        ("UPDATE credentials SET metadata=? WHERE id=?", ("not-json", f.identifier)),
        ("UPDATE credential_generations SET last_version=? WHERE credential_id=?", (2, f.identifier)),
        ("DELETE FROM credential_generations WHERE credential_id=?", (f.identifier,)),
        ("UPDATE credentials SET credential_version=? WHERE id=?", (9_007_199_254_740_991, f.identifier)),
    )
    for statement, parameters in mutations:
        with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(statement, parameters)
            altered = (f.core(conn), [tuple(row) for row in conn.execute("SELECT * FROM credential_generations")])
            changes = conn.total_changes
            refused(lambda: helper(conn, f.identifier, expected_version=1, secret=NEW), f.db.MetadataStoreError)
            assert conn.total_changes == changes
            assert (f.core(conn), [tuple(row) for row in conn.execute("SELECT * FROM credential_generations")]) == altered
            conn.rollback()
        assert f.snapshot() == before
    for generation in (True, 0, -1, 1.0, "1", 9_007_199_254_740_991):
        with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            refused(lambda: helper(conn, f.identifier, expected_version=generation, secret=NEW), ValueError)
            conn.rollback()
        assert f.snapshot() == before
    return {"binding_and_ledger_refusals": len(mutations), "generation_type_refusals": 6}


def postcommit_cache_failure():
    f = Fixture()
    from serverware import runtime
    before = f.snapshot()
    with patch.object(runtime, "invalidate_secret_leases", side_effect=RuntimeError("synthetic local cache failure")) as eviction:
        result = f.replace()
    assert eviction.call_count == 1
    assert result["key_replacement"]["cache_invalidation"] == "local_unconfirmed"
    assert result["key_replacement"]["in_flight_requests"] == "not_recalled"
    assert f.core()["credential_version"] == 2 and result["credential"]["credential_generation"] == 2
    assert f.catalog()["revision"] == f.created["revision"] + 1
    assert f.snapshot()[1:] == before[1:]
    assert len([row for row in workspace.rows(f.db, "audit_events") if row["event_type"] == EVENT]) == 1
    f.verify_secret(NEW)
    f.verify_privacy(result)
    return {"committed_once_despite_unconfirmed_local_cache": True}


def closed_input():
    f = Fixture()
    from pydantic import ValidationError
    before = f.snapshot()
    values = f.payload().model_dump()
    assert NEW not in repr(f.payload())
    for changes in ({"name": "renamed"}, {"header_name": "X-Different"}, {"auth_type": "header"},
            {"expected_credential_generation": True}, {"expected_credential_generation": "1"},
            {"secret": ""}, {"secret": "not\nprintable"}, {"secret": "x" * 8193}):
        refused(lambda: f.inputs.ReplaceCredentialKeyInput(**{**values, **changes}), ValidationError)
    assert f.snapshot() == before
    return {"closed_input_refusals": 8}


def persisted_receipt(config, db, store, bundles, schema):
    current = workspace.catalog(db, schema)
    identifier = current["credentials"][0]["id"]
    credential = db.get_credential(identifier, include_secret=True)
    assert credential is not None and credential["secret"] == NEW, "reopened encrypted key differs"
    workspace.verify_signed(config, db, store, bundles)
    return {"credential_id": identifier, "generation": credential["credential_version"],
        "application_ids": [row["id"] for row in current["applications"]],
        "rule_ids": [row["id"] for row in current["access_rules"]],
        "policy_hash": store.get_policy_high_water()["policy_hash"],
        "state_sha256": hashlib.sha256(repr(workspace.snapshot(db, catalog=True)).encode()).hexdigest()}


def create_for_restart():
    f = Fixture(shared=True)
    result = f.replace()
    f.verify_privacy(result)
    return persisted_receipt(f.config, f.db, f.store, f.bundles, f.schema)


def reopen():
    # A separate interpreter opens exactly the previous child's persisted state.
    config, db, store, bundles = workspace.common.backend(initialize=False)
    from serverware import operator_catalog_schema as schema
    before = workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()
    store.initialize()
    assert (workspace.snapshot(db, catalog=True), config.POLICY_BUNDLE_PATH.read_bytes()) == before
    return persisted_receipt(config, db, store, bundles, schema)


OPERATIONS = {
    "shared": lambda: successful(shared=True), "header": lambda: successful(header=True),
    "identical": lambda: successful(identical=True), "cas": stale_reviews,
    "missing-revoked": missing_and_revoked, "google": google_refused,
    "audit-rollback": audit_rollback, "concurrent": concurrent_single_winner,
    "helper-ownership": helper_ownership, "helper-integrity": helper_integrity,
    "cache-failure": postcommit_cache_failure, "input": closed_input,
    "create-restart": create_for_restart, "reopen": reopen,
}


class OperatorCredentialReplacementTests(unittest.TestCase):
    setUp = workspace.common.OperatorDemoPersistenceTests.setUp

    def run_worker(self, operation):
        completed = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(completed.returncode, 0, "\n".join(completed.stderr.splitlines()[-24:]))
        return json.loads(completed.stdout)

    def test_shared_identity_policy_encryption_and_same_transaction(self): self.run_worker("shared")
    def test_custom_header_placement_preserved(self): self.run_worker("header")
    def test_identical_secret_is_a_new_generation_without_old_decryption(self): self.run_worker("identical")
    def test_catalog_policy_and_core_cas_are_independent(self): self.run_worker("cas")
    def test_missing_and_revoked_credentials_refused(self): self.run_worker("missing-revoked")
    def test_audit_failure_rolls_back_all_replacement_state(self): self.run_worker("audit-rollback")
    def test_concurrent_same_review_has_exactly_one_winner(self): self.run_worker("concurrent")
    def test_helper_requires_profile_publication_transaction_and_real_store(self): self.run_worker("helper-ownership")
    def test_helper_refuses_disguised_oauth_malformed_metadata_and_generation_drift(self): self.run_worker("helper-integrity")
    def test_cache_failure_cannot_undo_or_repeat_commit(self): self.run_worker("cache-failure")
    def test_input_cannot_change_identity_or_placement(self): self.run_worker("input")

    def test_google_account_refused_without_provider_activity(self):
        import test_operator_catalog_google as google
        secret_file = Path(self.scratch.name) / "google-client-secret"
        secret_file.write_text(google.CLIENT_SECRET + "\n", encoding="utf-8")
        secret_file.chmod(0o600)
        self.environment.update(SERVERWARE_OPERATOR_GOOGLE_PROFILE="operator-google-v1",
            SERVERWARE_OPERATOR_DEMO_UPSTREAMS='["https://api.example.com","https://gmail.googleapis.com"]',
            SERVERWARE_PUBLIC_URL="https://control.example.com",
            SERVERWARE_GOOGLE_OAUTH_CLIENT_ID="123-fixture.apps.googleusercontent.com",
            SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI="https://control.example.com/api/oauth/callback/google",
            SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE=str(secret_file))
        self.run_worker("google")

    def test_replacement_persists_across_fresh_process_restart(self):
        created = self.run_worker("create-restart")
        self.assertEqual(created["generation"], 2)
        self.assertEqual(self.run_worker("reopen"), created)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        try:
            # Health alone is stubbed: it is unrelated to storage and must not
            # contact a gate. Publication, encryption and all CAS guards are real.
            from serverware import operator_demo_store
            with patch.object(operator_demo_store, "loaded_policy_hash", return_value=None):
                result = OPERATIONS[sys.argv[2]]()
            print(json.dumps(result, sort_keys=True))
        except Exception as error:
            # Never format exceptions/locals that may contain a submitted key.
            print("worker failure: " + type(error).__name__, file=sys.stderr)
            for frame in traceback.extract_tb(error.__traceback__)[-20:]:
                print(f"{Path(frame.filename).name}:{frame.lineno}:{frame.name}", file=sys.stderr)
            raise SystemExit(1) from None
    else:
        unittest.main(verbosity=2)
