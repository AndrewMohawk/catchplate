#!/usr/bin/env python3
"""Real local SQLite, encryption, signing and process-crash regression checks.

Run with application dependencies, preferably in a bounded network-none container
with the checkout read-only and TMPDIR on disposable storage. These tests import
the focused backend directly; no application server, provider or native authority
is started. Failure injection aborts real SQLite writes or exits a real child
process; it does not replace signing, encryption, persistence or profile guards.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_ENVIRONMENT = {
    "CATCHPLATE_OPERATOR_DEMO": "1",
    "CATCHPLATE_RELEASE_CHANNEL": "dev",
    "CATCHPLATE_PROCESS_MODE": "catchplate-control-plane",
    "CATCHPLATE_METADATA_STORE_BACKEND": "sqlite",
    "CATCHPLATE_AUDIT_STORE_BACKEND": "sqlite",
    "CATCHPLATE_GRANT_STORE_BACKEND": "sqlite",
    "CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
    "CATCHPLATE_KEY_RELEASE_REQUIRED": "0",
    "CATCHPLATE_DEV_AUTHENTICATOR": "0",
    "CATCHPLATE_DEV_DEMO_SEED": "0",
    "CATCHPLATE_OPERATOR_DEMO_UPSTREAMS": '["https://api.example.com"]',
    "CATCHPLATE_OPERATOR_DEMO_PROXY_URL": "https://proxy.example.com",
    "PYTHONDONTWRITEBYTECODE": "1",
}
_PROVIDER_SECRET = "synthetic-operator-persistence-provider-secret"
_ACTOR = "operator-persistence-test"
_TABLES = (
    "credentials", "credential_generations", "operator_demo_connections",
    "operator_demo_policy", "audit_events", "metadata_audit_outbox",
)
_FAILURES = {
    "credential": ("INSERT", "credentials"),
    "connection": ("INSERT", "operator_demo_connections"),
    "policy": ("UPDATE", "operator_demo_policy"),
    "audit": ("INSERT", "audit_events"),
}
_CRASH_EXIT = 73
_NONCE_KEY = "sha256:" + "1" * 64
_NONCE = "sha256:" + "2" * 64
_NOW = 1000


def backend(*, initialize=True):
    from catchplate import operator_demo
    operator_demo.activate()
    from catchplate import config, db, operator_demo_store, policy_bundle
    assert operator_demo.active()
    if initialize:
        db.init_db()
        operator_demo_store.initialize()
    return config, db, operator_demo_store, policy_bundle


def create_connection(store, *, methods=None):
    return store.create_connection(store.ConnectionInput(
        name="Persistence fixture", upstream_url="https://api.example.com/v1/items",
        methods=["GET"] if methods is None else methods, auth_type="bearer", secret=_PROVIDER_SECRET,
        response_fields=["status"],
    ), actor_id=_ACTOR)


def transaction_state(db):
    with closing(db.connect()) as connection:
        return {table: sorted(tuple(row) for row in connection.execute(
            f"SELECT * FROM {table}")) for table in _TABLES}


def verify_empty_policy(signed, initial_hash):
    """The schema's required placeholder must never grant a usable route."""
    assert signed["credentials"] == []
    assert signed["principals"] == [{"id": "agent:operator-demo:empty", "proxyAuthorization": {
        "scheme": "Bearer", "tokenId": "empty", "tokenSha256": initial_hash,
        "expiresAtEpochMs": 1}}]
    assert len(signed["routes"]) == 1
    route = signed["routes"][0]
    assert route["id"] == "operator.empty" and "credentialRef" not in route
    assert route["principals"] == ["agent:operator-demo:empty"]
    assert route["match"] == {"scheme": "https", "host": "api.example.com", "port": 443,
        "methods": ["GET"], "paths": ["/__catchplate_operator_demo_unconfigured__"]}
    assert route["adapter"]["type"] == "generic.rest"
    adapter = route["adapter"]["config"]
    assert adapter["credentialMode"] == "none"
    assert adapter["noCredentialProof"] == {"credentialRefAbsent": True,
        "secretInjectionDisabled": True, "sensitiveHeadersForwarded": False,
        "authorizationForwarded": False}
    assert adapter["request"] == {"allowedHeaders": [], "allowedQueryKeys": [],
        "allowedMediaTypes": [], "bodyMode": "none", "maxBodyBytes": 0,
        "operation": {"name": "operator.empty"}, "valueRules": []}
    assert adapter["response"] == {"mode": "headersOnly", "maxBodyBytes": 0,
        "contentTypes": [], "allowedHeaders": [], "error": {"mode": "json",
            "maxBodyBytes": 65536, "allowedFields": ["error", "code", "message"],
            "allowedHeaders": [], "onInvalid": "block"}}


def verify_committed(config, db, store, bundles, *, client_token=None):
    """Verify real signature, high water, encrypted secret and relational joins."""
    with closing(db.connect()) as connection:
        state = dict(connection.execute(
            "SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone())
        connections = [json.loads(row[0]) for row in connection.execute(
            "SELECT metadata_json FROM operator_demo_connections ORDER BY rowid")]
        credentials = [dict(row) for row in connection.execute("SELECT * FROM credentials")]
        events = [dict(row) for row in connection.execute(
            "SELECT * FROM audit_events WHERE event_type='operator_demo.connection.created'")]
        persisted = "\n".join(connection.iterdump()).encode()
    raw = state["signed_bundle_json"].encode()
    assert config.POLICY_BUNDLE_PATH.read_bytes() == raw
    signed = json.loads(raw)
    assert signed["defaults"] == {"action": "deny", "failMode": "closed",
        "unknownHosts": "block", "unknownPaths": "block", "validationFailure": "block"}
    compiled = bundles.compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
    assert compiled.hash == state["policy_hash"]
    assert bundles.verify_policy_high_water(compiled) == store.get_policy_high_water()
    loaded = bundles.get_policy_snapshot()
    assert loaded is not None, "committed signed policy was not loadable by the real policy loader"
    assert loaded.hash == compiled.hash
    assert state["sequence"] == len(connections) + 1
    assert len(credentials) == len(events) == len(connections)
    if connections:
        assert len(signed["routes"]) == len(signed["principals"]) == len(connections)
        assert all(route["id"] != "operator.empty" for route in signed["routes"])
    else:
        verify_empty_policy(signed, state["initial_hash"])
    audit_chain = db.verify_audit_chain()
    assert audit_chain["ok"] and audit_chain["complete"]
    assert audit_chain["count"] == len(events)
    credential_ids = {row["id"] for row in credentials}
    for row in connections:
        assert row["credential_id"] in credential_ids
        credential = db.get_credential(row["credential_id"], include_secret=True)
        assert credential["secret"] == _PROVIDER_SECRET
        ciphertext = next(item for item in credentials if item["id"] == row["credential_id"])
        assert ciphertext["encrypted_dek"] and ciphertext["secret_nonce"]
        assert ciphertext["secret_ciphertext"] and ciphertext["secret_kek_id"]
        assert "secret" not in row and "token" not in row
        event = next(item for item in events if json.loads(item["event_json"])["connection_id"] == row["id"])
        assert event["actor_id"] == _ACTOR
        assert json.loads(event["event_json"])["credential_id"] == row["credential_id"]
    secrets = [_PROVIDER_SECRET]
    if client_token is not None:
        secrets.append(client_token)
        digest = "sha256:" + hashlib.sha256(client_token.encode("ascii")).hexdigest()
        assert connections[-1]["token_sha256"] == digest
        assert signed["principals"][-1]["proxyAuthorization"]["tokenSha256"] == digest
    # Inspect only this test's newly created database/policy bytes, including WAL.
    files = [config.POLICY_BUNDLE_PATH, config.DB_PATH,
             Path(str(config.DB_PATH) + "-wal"), Path(str(config.DB_PATH) + "-shm")]
    for secret in secrets:
        assert secret.encode() not in persisted, "plaintext secret persisted in database rows"
        for path in files:
            if path.exists():
                assert secret.encode() not in path.read_bytes(), "plaintext secret persisted on disk"
    return {"sequence": state["sequence"], "policy_hash": compiled.hash,
            "connections": len(connections), "credentials": len(credentials), "audit_events": len(events)}


def fail_transaction(config, db, store, bundles, stage):
    create_connection(store)
    before = transaction_state(db)
    previous_file = config.POLICY_BUNDLE_PATH.read_bytes()
    operation, table = _FAILURES[stage]
    with closing(db.connect()) as connection, connection:
        connection.execute(f"""CREATE TRIGGER operator_test_abort AFTER {operation} ON {table}
            BEGIN SELECT RAISE(ABORT, 'operator persistence injected write failure'); END""")
    try:
        create_connection(store)
    except sqlite3.IntegrityError as error:
        assert "operator persistence injected write failure" in str(error)
    else:
        raise AssertionError("injected SQLite failure did not abort connection creation")
    finally:
        with closing(db.connect()) as connection, connection:
            connection.execute("DROP TRIGGER operator_test_abort")
    assert transaction_state(db) == before, "failed write left partial transaction state"
    assert config.POLICY_BUNDLE_PATH.read_bytes() == previous_file
    # A successful retry proves the failure was the actual write boundary.
    _, token, _ = create_connection(store)
    result = verify_committed(config, db, store, bundles, client_token=token)
    assert result["connections"] == 2
    return result


def replace_failure(config, db, store, bundles, *, crash):
    original = os.replace

    def replacement(source, destination, *args, **kwargs):
        if Path(destination) == config.POLICY_BUNDLE_PATH:
            # Check the committed transaction from another real DB connection.
            with closing(db.connect()) as connection:
                assert connection.execute("SELECT sequence FROM operator_demo_policy").fetchone()[0] == 2
                for table in ("credentials", "operator_demo_connections", "audit_events"):
                    assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 1
            if crash:
                os._exit(_CRASH_EXIT)
            raise OSError("operator persistence injected policy replace failure")
        return original(source, destination, *args, **kwargs)

    before = config.POLICY_BUNDLE_PATH.read_bytes()
    with patch.object(os, "replace", replacement):
        _, token, digest = create_connection(store)
    assert not crash, "process crash hook was never reached"
    assert config.POLICY_BUNDLE_PATH.read_bytes() == before
    assert store.get_policy_high_water()["policy_hash"] == digest
    assert bundles.get_policy_snapshot() is None, "stale file remained usable after new DB commit"
    store.materialize()
    return verify_committed(config, db, store, bundles, client_token=token)


def rollback_check(config, db, store, bundles):
    old_bytes = config.POLICY_BUNDLE_PATH.read_bytes()
    old = bundles.compile_policy_bundle(json.loads(old_bytes), verify_signature=True, validate_schema=True)
    create_connection(store)
    state = store.get_policy_high_water()
    try:
        bundles.verify_policy_high_water(old)
    except bundles.PolicyBundleError:
        pass
    else:
        raise AssertionError("previous correctly signed policy bypassed the committed high water")
    config.POLICY_BUNDLE_PATH.write_bytes(old_bytes)
    assert bundles.get_policy_snapshot() is None, "older signed policy file was loaded"
    assert store.get_policy_high_water() == state
    store.initialize()
    assert store.get_policy_high_water() == state
    return verify_committed(config, db, store, bundles)


def client_status_check(config, db, store, bundles):
    result = verify_committed(config, db, store, bundles)
    before = transaction_state(db)
    previous_file = config.POLICY_BUNDLE_PATH.read_bytes()
    with closing(db.connect()) as connection:
        row = json.loads(connection.execute("SELECT metadata_json FROM operator_demo_connections").fetchone()[0])
    expiry = row["token_expires_at_epoch_ms"]
    committed = result["policy_hash"]
    mismatched = "sha256:" + "0" * 64
    assert mismatched != committed
    # Only external health observation and wall time are controlled. The status
    # function reads the real committed SQLite connection and signed policy.
    for loaded in (committed, mismatched, None):
        for delta_ns in (-1, 0, 1):
            now_ns = expiry * 1_000_000 + delta_ns
            activation = "active" if loaded == committed else "pending"
            expected = "expired" if delta_ns >= 0 else "ready" if loaded == committed else "pending"
            with patch.object(store, "loaded_policy_hash", return_value=loaded), \
                    patch.object(store.time, "time_ns", return_value=now_ns):
                status = store.status()
            assert status["active_policy_hash"] == committed
            assert status["loaded_policy_hash"] == loaded
            assert len(status["connections"]) == 1
            public = status["connections"][0]
            assert public["activation"] == activation, (loaded, delta_ns, public)
            assert public["client_status"] == expected, (loaded, delta_ns, public)
            assert public["token_expires_at_epoch_ms"] == expiry
            assert public["policy_hash"] == committed
            assert "token_sha256" not in public and "secret" not in public
            assert transaction_state(db) == before, "status read changed durable state or renewed token"
            assert config.POLICY_BUNDLE_PATH.read_bytes() == previous_file
    return {**result, "token_expires_at_epoch_ms": expiry}


def worker(operation):
    config, db, store, bundles = backend(initialize=not operation.startswith("nonce-"))
    if operation == "bootstrap" or operation == "reopen":
        result = verify_committed(config, db, store, bundles)
    elif operation == "create":
        public, token, digest = create_connection(store)
        assert "secret" not in public and "token_sha256" not in public
        result = verify_committed(config, db, store, bundles, client_token=token)
        assert result["policy_hash"] == digest
    elif operation == "options-policy":
        public, token, digest = create_connection(store, methods=["OPTIONS"])
        result = verify_committed(config, db, store, bundles, client_token=token)
        signed = json.loads(config.POLICY_BUNDLE_PATH.read_bytes())
        assert public["methods"] == signed["routes"][0]["match"]["methods"] == ["OPTIONS"]
        assert signed["routes"][0]["adapter"]["config"]["response"]["mode"] == "json"
        assert result["policy_hash"] == digest
    elif operation in {"client-status", "client-status-reopen"}:
        if operation == "client-status":
            create_connection(store)
        result = client_status_check(config, db, store, bundles)
    elif operation.startswith("fail-"):
        result = fail_transaction(config, db, store, bundles, operation.removeprefix("fail-"))
    elif operation in {"replace-error", "crash"}:
        result = replace_failure(config, db, store, bundles, crash=operation == "crash")
    elif operation == "rollback":
        result = rollback_check(config, db, store, bundles)
    elif operation == "nonce-reserve":
        result = db.reserve_credential_lease_nonce(_NONCE_KEY, _NONCE, now_epoch_ms=_NOW)
    elif operation == "nonce-replay":
        assert db.credential_lease_nonce_reserved(_NONCE_KEY, _NONCE, now_epoch_ms=_NOW)
        assert db.reserve_credential_lease_nonce(_NONCE_KEY, _NONCE, now_epoch_ms=_NOW) == "replay"
        assert db.reserve_credential_lease_nonce("sha256:" + "3" * 64, _NONCE, now_epoch_ms=_NOW) is None
        result = "replay-refused-and-recipient-scoped"
    elif operation == "nonce-expiry":
        now = _NOW + 24 * 60 * 60 * 1000
        assert not db.credential_lease_nonce_reserved(_NONCE_KEY, _NONCE, now_epoch_ms=now)
        assert db.reserve_credential_lease_nonce(_NONCE_KEY, _NONCE, now_epoch_ms=now) is None
        result = "expiry-permits-new-reservation"
    elif operation == "nonce-invalid":
        for key, nonce, now in (("bad", _NONCE, _NOW), (_NONCE_KEY, "bad", _NOW),
                                (_NONCE_KEY, _NONCE, True), (_NONCE_KEY, _NONCE, -1),
                                (_NONCE_KEY, _NONCE, 1 << 63)):
            try:
                db.reserve_credential_lease_nonce(key, nonce, now_epoch_ms=now)
            except ValueError:
                pass
            else:
                raise AssertionError("invalid nonce reservation was admitted")
        with closing(db.connect()) as connection:
            assert connection.execute("SELECT COUNT(*) FROM operator_demo_nonces").fetchone()[0] == 0
        result = "invalid-refused-without-writes"
    else:
        raise AssertionError("unknown worker operation")
    print(json.dumps(result, sort_keys=True))


class OperatorDemoPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="catchplate-operator-persistence-",
            dir=os.getenv("TMPDIR", "/srv/catchplate-fast/tmp"))
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name) / "data"
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith("CATCHPLATE_")}
        self.environment.update(_ENVIRONMENT, CATCHPLATE_DATA_DIR=str(self.directory))

    def command(self, operation):
        return [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation]

    def run_worker(self, operation, *, expected_code=0):
        result = subprocess.run(self.command(operation), cwd=ROOT, env=self.environment,
                                text=True, capture_output=True, timeout=35)
        self.assertEqual(result.returncode, expected_code, "\n".join(result.stderr.splitlines()[-40:]))
        if expected_code:
            self.assertEqual(result.stdout, "")
            return None
        return json.loads(result.stdout)

    def test_encrypted_credentials_signed_policy_and_audit_survive_restart(self):
        created = self.run_worker("create")
        self.assertEqual(created["connections"], 1)
        self.assertEqual(self.run_worker("reopen"), created)

    def test_options_connection_commits_schema_valid_signed_policy(self):
        created = self.run_worker("options-policy")
        self.assertEqual(created["connections"], 1)
        self.assertEqual(self.run_worker("reopen"), created)

    def test_client_readiness_expiry_and_policy_mismatch_never_renew_on_restart(self):
        created = self.run_worker("client-status")
        self.assertEqual(created["connections"], 1)
        self.assertEqual(self.run_worker("client-status-reopen"), created)

    def test_credential_write_failure_rolls_back_all_transaction_state(self):
        self.run_worker("fail-credential")

    def test_connection_write_failure_rolls_back_all_transaction_state(self):
        self.run_worker("fail-connection")

    def test_policy_write_failure_rolls_back_all_transaction_state(self):
        self.run_worker("fail-policy")

    def test_audit_write_failure_rolls_back_all_transaction_state(self):
        self.run_worker("fail-audit")

    def test_policy_replace_error_keeps_commit_and_rejects_stale_file(self):
        self.assertEqual(self.run_worker("replace-error")["connections"], 1)

    def test_process_exit_after_commit_recovers_policy_file_on_restart(self):
        initial = self.run_worker("bootstrap")
        self.run_worker("crash", expected_code=_CRASH_EXIT)
        before_restart = json.loads((self.directory / "policy-bundle.json").read_bytes())
        self.assertEqual(before_restart["metadata"]["sequence"], 1)
        with closing(sqlite3.connect((self.directory / "catchplate.sqlite3").as_uri() + "?mode=ro", uri=True)) as connection:
            committed = connection.execute("SELECT sequence,policy_hash FROM operator_demo_policy").fetchone()
            self.assertEqual(committed[0], 2)
            self.assertNotEqual(committed[1], initial["policy_hash"])
        recovered = self.run_worker("reopen")
        self.assertEqual(recovered["sequence"], 2)
        self.assertEqual(recovered["policy_hash"], committed[1])
        self.assertEqual(recovered["connections"], 1)
        self.assertEqual(self.run_worker("reopen"), recovered)

    def test_older_correctly_signed_policy_is_refused_then_recovered(self):
        self.assertEqual(self.run_worker("rollback")["sequence"], 2)

    def test_nonce_replay_and_expiry_survive_process_restart(self):
        self.run_worker("bootstrap")
        self.assertIsNone(self.run_worker("nonce-reserve"))
        self.assertEqual(self.run_worker("nonce-replay"), "replay-refused-and-recipient-scoped")
        self.assertEqual(self.run_worker("nonce-expiry"), "expiry-permits-new-reservation")

    def test_concurrent_nonce_reservations_have_one_winner(self):
        self.run_worker("bootstrap")
        children = [subprocess.Popen(self.command("nonce-reserve"), cwd=ROOT, env=self.environment,
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        outcomes = []
        try:
            for child in children:
                output, error = child.communicate(timeout=35)
                self.assertEqual(child.returncode, 0, error)
                outcomes.append(json.loads(output))
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                child.stdout.close()
                child.stderr.close()
        self.assertCountEqual(outcomes, [None, "replay"])

    def test_invalid_nonce_values_are_refused_without_writes(self):
        self.run_worker("bootstrap")
        self.assertEqual(self.run_worker("nonce-invalid"), "invalid-refused-without-writes")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        worker(sys.argv[2])
    else:
        unittest.main(verbosity=2)
