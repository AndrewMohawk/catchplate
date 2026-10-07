#!/usr/bin/env python3
"""Real synthetic SQLite/policy tests; no providers, production or pilot state."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_ENVIRONMENT = {
    "SERVERWARE_DEVELOPMENT_SANDBOX": "1",
    "SERVERWARE_RELEASE_CHANNEL": "dev",
    "SERVERWARE_PROCESS_MODE": "serverware-control-plane",
    "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
    "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
    "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
    "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
    "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
    "SERVERWARE_CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES": "10000",
    "PYTHONDONTWRITEBYTECODE": "1",
}


def worker(operation: str) -> None:
    from serverware import development_sandbox as profile
    from serverware import development_sandbox_store as store
    if operation == "inactive":
        if profile.active():
            raise AssertionError("ordinary import activated the sandbox")
        for call in (store.get_policy_high_water,
                     lambda: store.commission_policy({}),
                     lambda: store.reserve_credential_lease_nonce("bad", "bad", now_epoch_ms=0)):
            try:
                call()
            except store.DevelopmentSandboxStoreError:
                pass
            else:
                raise AssertionError("inactive sandbox store was usable")
        from serverware import db
        try:
            db.get_policy_high_water()
        except db.PolicyCandidateAuthorityError:
            pass
        else:
            raise AssertionError("inactive SQLite became policy authority")
        print("inactive")
        return
    profile.activate()
    from serverware import db, policy_bundle as bundles
    digest = lambda byte: "sha256:" + byte * 64
    if operation == "initialize":
        db.init_db()
        db.init_db()
        with db.connect() as connection:
            assert connection.execute("SELECT COUNT(*) FROM rbac_authority_state").fetchone()[0] == 0
        print("initialized-twice-without-rbac-authority")
    elif operation == "commission":
        signed = bundles.sign_policy_bundle(bundles.demo_policy_bundle())
        state = store.commission_policy(signed)
        assert store.commission_policy(signed) == state
        assert db.get_policy_high_water() == state
        assert db.verify_policy_high_water(**{key: state[key] for key in (
            "policy_id", "sequence", "rollback_epoch", "policy_hash")}) == state
        assert db.get_policy_publication(state["policy_hash"])["status"] == "committed"
        changed = bundles.demo_policy_bundle()
        changed["metadata"]["sequence"] += 1
        try:
            store.commission_policy(bundles.sign_policy_bundle(changed))
        except store.DevelopmentSandboxStoreError:
            pass
        else:
            raise AssertionError("sandbox replaced its immutable fixture")
        assert store.get_policy_high_water() == state
        print(json.dumps(state, sort_keys=True))
    elif operation == "reserve":
        print(json.dumps(db.reserve_credential_lease_nonce(digest("1"), digest("2"), now_epoch_ms=1000)))
    elif operation == "replay":
        assert db.credential_lease_nonce_reserved(digest("1"), digest("2"), now_epoch_ms=1000)
        assert db.reserve_credential_lease_nonce(digest("1"), digest("2"), now_epoch_ms=1000) == "replay"
        assert db.reserve_credential_lease_nonce(digest("1"), digest("3"), now_epoch_ms=1000) is None
        # Populate only synthetic nonce fixtures to the real configured floor;
        # the last-slot, replay and expiry decisions use the actual public API.
        with store._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.executemany("INSERT INTO sandbox_credential_nonces VALUES (?, ?, ?)",
                ((digest("1"), "sha256:" + format(index, "064x"), 1000 + 24 * 60 * 60 * 1000)
                 for index in range(9998)))
            connection.commit()
        assert db.reserve_credential_lease_nonce(digest("1"), digest("4"), now_epoch_ms=1000) == "capacity"
        assert db.reserve_credential_lease_nonce(digest("1"), digest("2"), now_epoch_ms=1000) == "replay"
        print("replay-and-capacity")
    elif operation == "expiry":
        now = 1000 + 24 * 60 * 60 * 1000
        assert not db.credential_lease_nonce_reserved(digest("1"), digest("2"), now_epoch_ms=now)
        assert db.reserve_credential_lease_nonce(digest("1"), digest("2"), now_epoch_ms=now) is None
        print("expired-and-reused")
    elif operation == "invalid":
        for key, nonce, now in (("x", digest("1"), 1), (digest("1"), "y", 1),
                                (digest("1"), digest("2"), True),
                                (digest("1"), digest("2"), -1),
                                (digest("1"), digest("2"), 1 << 63)):
            try:
                store.reserve_credential_lease_nonce(key, nonce, now_epoch_ms=now)
            except store.DevelopmentSandboxStoreError:
                pass
            else:
                raise AssertionError("invalid nonce admitted")
        print("invalid-rejected")
    else:
        raise AssertionError("unknown worker operation")


class DevelopmentSandboxStoreTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="serverware-sandbox-store-",
            dir=os.getenv("TMPDIR", "/srv/catchplate-fast/tmp"))
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name) / "data"
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith("SERVERWARE_")}
        self.environment.update(_ENVIRONMENT, SERVERWARE_DATA_DIR=str(self.directory))

    def command(self, operation):
        return [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation]

    def run_worker(self, operation, *, environment=None):
        result = subprocess.run(self.command(operation), cwd=ROOT,
            env=environment or self.environment, text=True, capture_output=True, timeout=25)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_inactive_profile_has_no_store_effect(self):
        self.assertEqual(self.run_worker("inactive"), "inactive")
        self.assertFalse(self.directory.exists())

    def test_production_profile_cannot_create_store(self):
        environment = dict(self.environment, SERVERWARE_PRODUCTION_IMAGE="1")
        result = subprocess.run(self.command("commission"), cwd=ROOT, env=environment,
                                text=True, capture_output=True, timeout=25)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("explicit non-production", result.stderr)
        self.assertFalse(self.directory.exists())

    def test_actual_metadata_schema_initializes_and_reopens(self):
        self.assertEqual(self.run_worker("initialize"), "initialized-twice-without-rbac-authority")
        self.assertEqual(self.run_worker("initialize"), "initialized-twice-without-rbac-authority")

    def test_commission_is_signed_immutable_and_restart_idempotent(self):
        first = self.run_worker("commission")
        self.assertEqual(first, self.run_worker("commission"))
        self.assertTrue((self.directory / "development-sandbox.sqlite3").is_file())
        self.assertFalse((self.directory / "serverware.sqlite3").exists())

    def test_nonce_replay_capacity_expiry_survive_process_restart(self):
        self.run_worker("commission")
        self.assertEqual(self.run_worker("reserve"), "null")
        self.assertEqual(self.run_worker("replay"), "replay-and-capacity")
        self.assertEqual(self.run_worker("expiry"), "expired-and-reused")

    def test_simultaneous_reservation_has_exactly_one_winner(self):
        self.run_worker("commission")
        children = [subprocess.Popen(self.command("reserve"), cwd=ROOT,
            env=self.environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for _ in range(2)]
        outcomes = []
        try:
            for child in children:
                out, err = child.communicate(timeout=25)
                self.assertEqual(child.returncode, 0, err)
                outcomes.append(out.strip())
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                child.stdout.close()
                child.stderr.close()
        self.assertCountEqual(outcomes, ["null", '"replay"'])

    def test_invalid_nonce_values_fail_closed(self):
        self.run_worker("commission")
        self.assertEqual(self.run_worker("invalid"), "invalid-rejected")

    def test_sqlite_regex_translation_preserves_constraints_and_literals(self):
        from serverware.authority_store import metadata_schema as schema
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        source = """CREATE TABLE test (digest TEXT CHECK(digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'),
            display TEXT DEFAULT 'literal ~ text'); -- comment ~ unchanged
        """
        schema._sqlite_execute_fixed_statements(connection, source)
        connection.execute("INSERT INTO test(digest) VALUES (?)", ("sha256:" + "a" * 64,))
        self.assertEqual(connection.execute("SELECT display FROM test").fetchone()[0], "literal ~ text")
        for value in ("sha256:" + "G" * 64, "sha256:" + "a" * 63,
                      "sha256:" + "a" * 64 + "\n", "x" + "sha256:" + "a" * 64):
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("INSERT INTO test(digest) VALUES (?)", (value,))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        worker(sys.argv[2])
    else:
        unittest.main()
