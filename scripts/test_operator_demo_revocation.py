#!/usr/bin/env python3
"""Isolated revocation transactions using actual SQLite, signing and audit.

Only failure boundaries and external gate-health observations are controlled.
No production admission guard, cryptography, database or authority is replaced.
Every worker has a separate explicitly selected operator-development data root.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

import test_operator_demo_persistence as common

ROOT = Path(__file__).resolve().parents[1]
TABLES = (*common._TABLES, "operator_demo_revocations")
RECEIPT_FIELDS = {"connection_id", "name", "credential_id", "principal_id", "revoked_at",
    "expected_policy_hash", "revocation_policy_hash", "sequence"}
CRASH_EXIT = 74
FAILURES = {"credential": ("DELETE", "credentials"),
    "connection": ("DELETE", "operator_demo_connections"),
    "tombstone": ("INSERT", "operator_demo_revocations"),
    "policy": ("UPDATE", "operator_demo_policy"), "audit": ("INSERT", "audit_events")}


def state(db):
    with closing(db.connect()) as connection:
        return {table: sorted(tuple(row) for row in connection.execute(f"SELECT * FROM {table}"))
            for table in TABLES}


def read_rows(db, table):
    with closing(db.connect()) as connection:
        return [dict(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")]


def create(store, name="Revocation fixture"):
    return store.create_connection(store.ConnectionInput(name=name,
        upstream_url="https://api.example.com/v1/items", methods=["GET"],
        auth_type="bearer", secret=common._PROVIDER_SECRET, response_fields=["status"]),
        actor_id=common._ACTOR)


def revoke(store, public, expected):
    return store.revoke_connection(store.RevocationInput(
        connection_id=public["id"], expected_policy_hash=expected), actor_id=common._ACTOR)


def verify(config, db, store, bundles):
    policy = read_rows(db, "operator_demo_policy")[0]
    raw = policy["signed_bundle_json"].encode()
    assert config.POLICY_BUNDLE_PATH.read_bytes() == raw
    signed = json.loads(raw)
    compiled = bundles.compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
    assert compiled.hash == policy["policy_hash"]
    assert bundles.verify_policy_high_water(compiled) == store.get_policy_high_water()
    snapshot = bundles.get_policy_snapshot()
    assert snapshot is not None and snapshot.hash == compiled.hash
    connections = [json.loads(row["metadata_json"]) for row in read_rows(db, "operator_demo_connections")]
    tombstones = [json.loads(row["receipt_json"]) for row in read_rows(db, "operator_demo_revocations")]
    credentials = read_rows(db, "credentials")
    events = read_rows(db, "audit_events")
    assert policy["sequence"] == 1 + sum(row["event_type"] in {
        "operator_demo.connection.created", "operator_demo.connection.revoked"} for row in events)
    assert len(credentials) == len(connections)
    assert {row["id"] for row in credentials} == {row["credential_id"] for row in connections}
    assert {item["id"] for item in signed["credentials"]} == {row["credential_id"] for row in connections}
    if connections:
        assert {item["id"] for item in signed["principals"]} == {row["principal_id"] for row in connections}
        assert {item["id"] for item in signed["routes"]} == {"operator." + row["id"] for row in connections}
    else:
        common.verify_empty_policy(signed, policy["initial_hash"])
    revoked = {row["connection_id"] for row in tombstones}
    assert not revoked.intersection(row["id"] for row in connections)
    for receipt in tombstones:
        assert set(receipt) == RECEIPT_FIELDS
        matching = [row for row in events if row["event_type"] == "operator_demo.connection.revoked"
            and json.loads(row["event_json"])["connection_id"] == receipt["connection_id"]]
        assert len(matching) == 1 and json.loads(matching[0]["event_json"]) == receipt
        assert matching[0]["actor_id"] == common._ACTOR
        assert db.get_credential(receipt["credential_id"], include_secret=True) is None
    chain = db.verify_audit_chain()
    assert chain["ok"] and chain["complete"] and chain["count"] == len(events)
    return {"sequence": policy["sequence"], "policy_hash": policy["policy_hash"],
        "connections": len(connections), "revocations": len(tombstones), "events": len(events)}


def basic(config, db, store, bundles, *, last):
    first, token, expected = create(store, "Revoked fixture")
    other = None
    if not last:
        other, _, expected = create(store, "Preserved fixture")
    before = state(db)
    generation_before = read_rows(db, "credential_generations")
    first_metadata = json.loads(read_rows(db, "operator_demo_connections")[0]["metadata_json"])
    receipt = revoke(store, first, expected)
    assert receipt["connection_id"] == first["id"] and receipt["credential_id"] == first["credential_id"]
    assert receipt["principal_id"] == first["principal_id"] and receipt["expected_policy_hash"] == expected
    assert receipt["sequence"] == (3 if last else 4)
    assert read_rows(db, "credential_generations") == generation_before, "revocation erased generation history"
    after = state(db)
    assert len(after["audit_events"]) == len(before["audit_events"]) + 1
    assert all(row in after["audit_events"] for row in before["audit_events"])
    if other:
        assert after["operator_demo_connections"] == [row for row in before["operator_demo_connections"] if row[0] == other["id"]]
        assert after["credentials"] == [row for row in before["credentials"] if row[0] == other["credential_id"]]
    for row in read_rows(db, "operator_demo_revocations"):
        raw = row["receipt_json"]
        for secret in (common._PROVIDER_SECRET, token, first_metadata["token_sha256"]):
            assert secret not in raw
        assert not {"secret", "client_token", "token_sha256", "secret_ciphertext", "encrypted_dek"}.intersection(json.loads(raw))
    assert first_metadata["token_sha256"] not in config.POLICY_BUNDLE_PATH.read_text()
    result = verify(config, db, store, bundles)
    # A lost response is retried with the original review hash, not the new hash.
    for _ in range(2):
        assert revoke(store, first, expected) == receipt
        assert state(db) == after and verify(config, db, store, bundles) == result
    try:
        revoke(store, first, receipt["revocation_policy_hash"])
    except store.RevocationConflict:
        pass
    else:
        raise AssertionError("replay accepted a different review hash")
    assert state(db) == after
    return result


def failure(config, db, store, bundles, stage):
    public, _, expected = create(store)
    before, file_before = state(db), config.POLICY_BUNDLE_PATH.read_bytes()
    if stage == "signing":
        with patch.object(bundles, "sign_policy_bundle", side_effect=RuntimeError("synthetic signer unavailable")):
            try:
                revoke(store, public, expected)
            except RuntimeError as error:
                assert str(error) == "synthetic signer unavailable"
            else:
                raise AssertionError("signing failure was ignored")
    else:
        operation, table = FAILURES[stage]
        with closing(db.connect()) as connection, connection:
            connection.execute(f"CREATE TRIGGER revoke_test_abort AFTER {operation} ON {table} "
                "BEGIN SELECT RAISE(ABORT, 'synthetic revocation write failure'); END")
        try:
            revoke(store, public, expected)
        except sqlite3.IntegrityError as error:
            assert "synthetic revocation write failure" in str(error)
        else:
            raise AssertionError("SQLite failure did not abort revocation")
        finally:
            with closing(db.connect()) as connection, connection:
                connection.execute("DROP TRIGGER revoke_test_abort")
    assert state(db) == before, "failed revocation partially committed"
    assert config.POLICY_BUNDLE_PATH.read_bytes() == file_before
    revoke(store, public, expected)
    return verify(config, db, store, bundles)


def rejection(config, db, store, bundles):
    public, _, old_hash = create(store)
    other, _, current = create(store, "Other fixture")
    before = state(db)
    for identifier, expected, exception in ((public["id"], old_hash, store.RevocationConflict),
            (str(uuid.uuid4()), old_hash, store.RevocationNotFound)):
        try:
            revoke(store, {"id": identifier}, expected)
        except exception:
            pass
        else:
            raise AssertionError("stale or missing revocation target was admitted")
        assert state(db) == before
    # Test database corruption of the binding, not a replacement of its guard.
    with closing(db.connect()) as connection, connection:
        original = connection.execute("SELECT metadata_json FROM operator_demo_connections WHERE id=?", (public["id"],)).fetchone()[0]
        wrong = json.loads(original)
        wrong["credential_id"] = other["credential_id"]
        connection.execute("UPDATE operator_demo_connections SET metadata_json=? WHERE id=?", (json.dumps(wrong), public["id"]))
    corrupted = state(db)
    try:
        revoke(store, public, current)
    except store.RevocationConflict:
        pass
    else:
        raise AssertionError("revocation deleted another connection's credential")
    assert state(db) == corrupted
    with closing(db.connect()) as connection, connection:
        connection.execute("UPDATE operator_demo_connections SET metadata_json=? WHERE id=?", (original, public["id"]))
    assert state(db) == before
    return verify(config, db, store, bundles)


def observation(config, db, store, bundles):
    public, _, expected = create(store)
    original_row = read_rows(db, "operator_demo_connections")[0]
    receipt = revoke(store, public, expected)
    for create_later in (False, True):
        if create_later:
            create(store, "Later connection")
        current = store.get_policy_high_water()["policy_hash"]
        before = state(db)
        for loaded in (None, expected, receipt["revocation_policy_hash"], current):
            with patch.object(store, "loaded_policy_hash", return_value=loaded):
                result = store.revoke_result(public["id"])
                status = store.status()
            enforced = "enforced" if loaded == current else "pending"
            assert result["policy_hash"] == current and result["loaded_policy_hash"] == loaded
            assert result["revocation"] == {**receipt, "policy_hash": current, "enforcement": enforced}
            assert status["revocations"] == [result["revocation"]]
            assert status["active_policy_hash"] == current
            assert revoke(store, public, expected) == receipt
            assert state(db) == before, "observation or exact replay mutated state"
    # An inconsistent reappearing target must never be called enforced merely
    # because the observed gate hash matches. The fixture is removed afterward.
    with closing(db.connect()) as connection, connection:
        connection.execute("INSERT INTO operator_demo_connections VALUES (?,?)",
            (original_row["id"], original_row["metadata_json"]))
    with patch.object(store, "loaded_policy_hash", return_value=current):
        assert store.revoke_result(public["id"])["revocation"]["enforcement"] == "pending"
        assert store.status()["revocations"][0]["enforcement"] == "pending"
    corrupted = state(db)
    try:
        revoke(store, public, expected)
    except store.RevocationConflict:
        pass
    else:
        raise AssertionError("exact replay ignored a reappearing active target")
    assert state(db) == corrupted
    with closing(db.connect()) as connection, connection:
        connection.execute("DELETE FROM operator_demo_connections WHERE id=?", (public["id"],))
    assert state(db) == before
    return verify(config, db, store, bundles)


def materialization(config, db, store, bundles, *, crash):
    public, _, expected = create(store)
    old_file = config.POLICY_BUNDLE_PATH.read_bytes()
    replace = os.replace

    def fail_replace(source, destination, *args, **kwargs):
        if Path(destination) == config.POLICY_BUNDLE_PATH:
            assert len(read_rows(db, "operator_demo_revocations")) == 1
            assert read_rows(db, "credentials") == [] and read_rows(db, "operator_demo_connections") == []
            if crash:
                os._exit(CRASH_EXIT)
            raise OSError("synthetic revocation materialization failure")
        return replace(source, destination, *args, **kwargs)

    with patch.object(os, "replace", fail_replace):
        receipt = revoke(store, public, expected)
    assert not crash and config.POLICY_BUNDLE_PATH.read_bytes() == old_file
    assert store.get_policy_high_water()["policy_hash"] == receipt["revocation_policy_hash"]
    assert bundles.get_policy_snapshot() is None, "revoked signed policy remained loadable after commit"
    with patch.object(store, "loaded_policy_hash", return_value=expected):
        assert store.revoke_result(public["id"])["revocation"]["enforcement"] == "pending"
    # Exact replay does not need another mutation; startup rematerializes the commit.
    assert revoke(store, public, expected) == receipt
    store.initialize()
    return verify(config, db, store, bundles)


def capacity(config, db, store, bundles):
    retained = []
    for index in range(store.MAX_ACTIVE_CONNECTIONS):
        public, _, current = create(store, "Capacity fixture " + str(index))
        retained.append(public)
    before = state(db)
    try:
        create(store)
    except store.ConnectionLimitReached as error:
        assert error.reason == "active"
    else:
        raise AssertionError("active connection bound was ignored")
    assert state(db) == before
    revoke(store, retained[0], current)
    replacement, _, _ = create(store)
    assert replacement["id"] not in {row["id"] for row in retained}
    assert len(read_rows(db, "operator_demo_connections")) == store.MAX_ACTIVE_CONNECTIONS
    assert len(state(db)["credential_generations"]) == len(retained) + 1
    assert all(row in state(db)["credential_generations"] for row in before["credential_generations"])
    with patch.object(store, "loaded_policy_hash", return_value=None):
        limits = store.status()["connection_limits"]
    assert limits == {"active_max": 32, "retained_max": 1024, "active_count": 32, "retained_count": 33}
    return verify(config, db, store, bundles)


def retained_capacity(config, db, store, bundles):
    target, _, _ = create(store)
    retired, _, current = create(store, "Retired capacity fixture")
    receipt = revoke(store, retired, current)
    current = store.get_policy_high_water()["policy_hash"]
    # Bounded synthetic retained-history fixture avoids1024 separate signatures.
    # It changes no production guard; the actual SQLite count controls admission.
    with closing(db.connect()) as connection, connection:
        for _ in range(store.MAX_RETAINED_CONNECTIONS - 2):
            identifier = str(uuid.uuid4())
            historical = {**receipt, "connection_id": identifier,
                "principal_id": "agent:operator-demo:" + identifier}
            connection.execute("INSERT INTO operator_demo_revocations VALUES (?,?)",
                (identifier, json.dumps(historical, sort_keys=True)))
    before = state(db)
    try:
        create(store)
    except store.ConnectionLimitReached as error:
        assert error.reason == "retained"
    else:
        raise AssertionError("retained-history bound was ignored")
    assert state(db) == before
    terminal = revoke(store, target, current)
    assert revoke(store, target, current) == terminal
    with patch.object(store, "loaded_policy_hash", return_value=None):
        limits = store.status()["connection_limits"]
    assert limits == {"active_max": 32, "retained_max": 1024, "active_count": 0, "retained_count": 1024}
    chain = db.verify_audit_chain()
    assert chain["ok"] and chain["complete"] and chain["count"] == 4
    return {"retained_count": 1024, "revocation_remained_available": True}


def identifier_reuse(config, db, store, bundles):
    public, _, current = create(store)
    revoke(store, public, current)
    before = state(db)
    with patch.object(store.uuid, "uuid4", return_value=uuid.UUID(public["id"])):
        try:
            create(store)
        except RuntimeError:
            pass
        else:
            raise AssertionError("creation reused a revoked connection identity")
    assert state(db) == before
    return verify(config, db, store, bundles)


def worker(operation):
    config, db, store, bundles = common.backend()
    if operation in {"reopen", "bootstrap"}:
        result = verify(config, db, store, bundles)
    elif operation == "create-only":
        create(store)
        result = verify(config, db, store, bundles)
    elif operation == "revoke-existing":
        event = next(row for row in read_rows(db, "audit_events")
            if row["event_type"] == "operator_demo.connection.created")
        original = json.loads(event["event_json"])
        result = revoke(store, {"id": original["connection_id"]}, original["policy_hash"])
    elif operation.startswith("fail-"):
        result = failure(config, db, store, bundles, operation.removeprefix("fail-"))
    elif operation in {"last", "preserve-other"}:
        result = basic(config, db, store, bundles, last=operation == "last")
    elif operation in {"replace-error", "crash"}:
        result = materialization(config, db, store, bundles, crash=operation == "crash")
    else:
        result = {"reject": rejection, "observation": observation, "capacity": capacity,
            "retained-capacity": retained_capacity, "identifier-reuse": identifier_reuse}[operation](config, db, store, bundles)
    print(json.dumps(result, sort_keys=True))


class OperatorDemoRevocationTests(unittest.TestCase):
    setUp = common.OperatorDemoPersistenceTests.setUp

    def run_worker(self, operation, expected=0):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, expected, "\n".join(result.stderr.splitlines()[-40:]))
        return json.loads(result.stdout) if expected == 0 else None

    def test_last_connection_uses_expired_deny_only_sentinel_and_replays(self):
        result = self.run_worker("last")
        self.assertEqual(result["connections"], 0)
        self.assertEqual(self.run_worker("reopen"), result)

    def test_other_connection_and_generation_history_are_preserved(self):
        self.assertEqual(self.run_worker("preserve-other")["connections"], 1)

    def test_signing_failure_rolls_back(self):
        self.run_worker("fail-signing")

    def test_credential_delete_failure_rolls_back(self):
        self.run_worker("fail-credential")

    def test_connection_delete_failure_rolls_back(self):
        self.run_worker("fail-connection")

    def test_tombstone_failure_rolls_back(self):
        self.run_worker("fail-tombstone")

    def test_policy_write_failure_rolls_back(self):
        self.run_worker("fail-policy")

    def test_audit_write_failure_rolls_back(self):
        self.run_worker("fail-audit")

    def test_stale_unknown_and_changed_binding_are_read_only_failures(self):
        self.run_worker("reject")

    def test_enforcement_tracks_current_hash_even_after_later_creation(self):
        self.run_worker("observation")

    def test_materialization_failure_retains_revocation_and_recovers(self):
        self.run_worker("replace-error")

    def test_process_crash_after_commit_recovers_without_second_revoke(self):
        self.run_worker("bootstrap")
        self.run_worker("crash", expected=CRASH_EXIT)
        signed = json.loads((self.directory / "policy-bundle.json").read_bytes())
        self.assertEqual(signed["metadata"]["sequence"], 2)
        with closing(sqlite3.connect((self.directory / "catchplate.sqlite3").as_uri() + "?mode=ro", uri=True)) as connection:
            self.assertEqual(connection.execute("SELECT sequence FROM operator_demo_policy").fetchone()[0], 3)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM credentials").fetchone()[0], 0)
        recovered = self.run_worker("reopen")
        self.assertEqual(recovered["revocations"], 1)
        self.assertEqual(recovered["connections"], 0)
        self.assertEqual(recovered["sequence"], 3)
        self.assertEqual(self.run_worker("reopen"), recovered)

    def test_revocation_frees_active_capacity(self):
        self.run_worker("capacity")

    def test_retained_capacity_blocks_creation_not_revocation_or_replay(self):
        self.run_worker("retained-capacity")

    def test_creation_cannot_reuse_tombstoned_identifier(self):
        self.run_worker("identifier-reuse")

    def test_concurrent_exact_replays_commit_one_revocation(self):
        self.run_worker("create-only")
        command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", "revoke-existing"]
        children = [subprocess.Popen(command, cwd=ROOT, env=self.environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        results = []
        try:
            for child in children:
                output, error = child.communicate(timeout=60)
                self.assertEqual(child.returncode, 0, "\n".join(error.splitlines()[-40:]))
                results.append(json.loads(output))
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                child.stdout.close()
                child.stderr.close()
        self.assertEqual(results[0], results[1])
        recovered = self.run_worker("reopen")
        self.assertEqual(recovered["sequence"], 3)
        self.assertEqual(recovered["revocations"], 1)
        self.assertEqual(recovered["events"], 2)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        worker(sys.argv[2])
    else:
        unittest.main(verbosity=2)
