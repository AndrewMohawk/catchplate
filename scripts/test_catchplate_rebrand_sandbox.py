#!/usr/bin/env python3
"""Synthetic, offline sandbox-copy and restart checks; never a live store."""
from __future__ import annotations

from copy import deepcopy
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SECRET = "synthetic-serverware-sandbox-secret-unchanged"


def configure(directory):
    from test_development_sandbox_store import _ENVIRONMENT
    os.environ.update(_ENVIRONMENT, CATCHPLATE_DATA_DIR=str(directory),
        CATCHPLATE_DEV_AUTHENTICATOR="1", CATCHPLATE_DEV_DEMO_SEED="1")


def fixture(directory):
    os.umask(0o077)
    configure(directory)
    from catchplate import development_sandbox as profile, development_sandbox_store as store
    from catchplate import db, policy_bundle as bundles
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from test_catchplate_rebrand_migration import old_envelope
    profile.activate()
    db.init_db()
    profile.bootstrap()
    (directory / "response-signing-ed25519.pem").write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    policy = bundles.demo_policy_bundle()
    policy["apiVersion"] = "serverware.policy/v1"
    policy["metadata"].update(id="serverware-demo", sequence=7, rollbackEpoch=2)
    for principal in policy["principals"]:
        principal["requiredHeaders"]["X-Serverware-Agent"] = principal["requiredHeaders"].pop("X-Catchplate-Agent")
    policy = bundles.sign_policy_bundle(policy)
    raw = bundles.canonical_json(policy)
    unsigned = deepcopy(policy)
    unsigned["metadata"].pop("signature")
    digest = "sha256:" + hashlib.sha256(bundles.canonical_json(unsigned).encode()).hexdigest()
    with store._connect() as conn:
        conn.execute("UPDATE sandbox_policy SET policy_id=?,sequence=7,rollback_epoch=2,policy_hash=?,signed_bundle_json=?",
            ("serverware-demo", digest, raw))
        conn.executemany("INSERT INTO sandbox_credential_nonces VALUES (?,?,?)", [
            ("sha256:" + "1" * 64, "sha256:" + "2" * 64, 1),
            ("sha256:" + "1" * 64, "sha256:" + "3" * 64, 4102444800000)])
    (directory / "policy-bundle.json").write_text(raw)
    with closing(db.connect()) as conn:
        master = (directory / "master.key").read_bytes()
        row = conn.execute("SELECT * FROM credentials").fetchone()
        envelope = old_envelope(dict(row), master, SECRET)
        conn.execute("UPDATE credentials SET encrypted_dek=?,secret_nonce=?,secret_ciphertext=?",
            tuple(envelope.values()))
        db.append_audit_event(conn, event_type="serverware.synthetic.history", actor_type="system", actor_id=None,
            event={"schema": "serverware.synthetic/v1", "opaque": "serverware historical bytes"})
        conn.execute("ALTER TABLE catchplate_store_migrations RENAME TO serverware_store_migrations")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    (directory / "catchplate.sqlite3").rename(directory / "serverware.sqlite3")
    (directory / "catchplate.sqlite3.migration.lock").rename(directory / "serverware.sqlite3.migration.lock")
    (directory / ".catchplate-development-sandbox.json").rename(directory / ".serverware-development-sandbox.json")
    (directory / ".serverware-development-sandbox.json").write_bytes(
        b'{"schema": "serverware.developmentSandbox/v1", "syntheticOnly": true}\n')
    for path in directory.iterdir():
        if path.is_file():
            path.chmod(0o644 if path.name.endswith((".pub.pem", "-cert.pem")) else 0o600)


def run_worker(*args):
    env = {key: value for key, value in os.environ.items() if not key.startswith(("CATCHPLATE_", "SERVERWARE_"))}
    return subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), *map(str, args)],
        cwd=ROOT, env=env, capture_output=True, timeout=45)


def files(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*") if path.is_file()}


def retained(root):
    result = {name: value for name, value in files(root).items()
        if not name.endswith((".sqlite3", ".sqlite3-wal", ".sqlite3-shm"))}
    for name in ("catchplate.sqlite3", "development-sandbox.sqlite3", "webauthn-recovery-witness.sqlite3"):
        with closing(sqlite3.connect((root / name).as_uri() + "?mode=ro", uri=True)) as conn:
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
                # Only a digest is exposed on failure, never stored row contents.
                values = conn.execute('SELECT * FROM "' + row[0] + '" ORDER BY rowid').fetchall()
                result[name + ":" + row[0]] = hashlib.sha256(repr(values).encode()).hexdigest()
    return result


class SandboxMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seed_temp = tempfile.TemporaryDirectory(prefix="catchplate-sandbox-seed-")
        cls.seed = Path(cls.seed_temp.name) / "data"
        result = run_worker("fixture", cls.seed)
        if result.returncode:
            raise AssertionError(result.stderr.decode()[-3500:])

    @classmethod
    def tearDownClass(cls):
        cls.seed_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="catchplate-sandbox-migration-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.target = self.root / "source", self.root / "target"
        shutil.copytree(self.seed, self.source)
        self.target.mkdir(mode=0o700)

    def migrate(self):
        return run_worker("migrate", self.source, self.target)

    def test_real_copy_and_bootstrap_preserve_rows_keys_nonces_and_authority(self):
        original = files(self.source)
        result = self.migrate()
        self.assertEqual(result.returncode, 0, result.stderr.decode()[-4000:])
        self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)
        self.assertEqual(files(self.source), original)
        self.assertFalse((self.target / "rebrand-incomplete.json").exists())
        receipt = json.loads((self.target / "rebrand-receipt.json").read_bytes())
        self.assertEqual(receipt["policy_lineage"]["source"]["sequence"], 7)
        self.assertEqual(receipt["policy_lineage"]["target"]["sequence"], 8)
        self.assertEqual(receipt["policy_lineage"]["target"]["rollbackEpoch"], 2)
        self.assertFalse(receipt["gatePersistentHighWater"])
        for name in ("master.key", "policy-signing-ed25519.pem", "policy-signing-ed25519.pub.pem", "response-signing-ed25519.pem"):
            self.assertEqual(hashlib.sha256((self.target / name).read_bytes()).hexdigest(), original[name])
        with closing(sqlite3.connect(self.source / "serverware.sqlite3")) as old, closing(sqlite3.connect(self.target / "catchplate.sqlite3")) as new:
            for table in ("routes", "audit_events", "credential_generations", "credential_lease_replay_state"):
                self.assertEqual(old.execute("SELECT rowid,* FROM " + table).fetchall(), new.execute("SELECT rowid,* FROM " + table).fetchall())
            self.assertIsNotNone(new.execute("SELECT 1 FROM sqlite_master WHERE name='catchplate_store_migrations'").fetchone())
        with closing(sqlite3.connect(self.source / "development-sandbox.sqlite3")) as old, closing(sqlite3.connect(self.target / "development-sandbox.sqlite3")) as new:
            self.assertEqual(old.execute("SELECT rowid,* FROM sandbox_credential_nonces").fetchall(),
                new.execute("SELECT rowid,* FROM sandbox_credential_nonces").fetchall())
            self.assertEqual(old.execute("SELECT updated_at FROM sandbox_policy").fetchone(),
                new.execute("SELECT updated_at FROM sandbox_policy").fetchone())
        before = retained(self.target)
        reopened = run_worker("reopen", self.target)
        self.assertEqual(reopened.returncode, 0, reopened.stderr.decode()[-3500:])
        self.assertEqual(retained(self.target), before)
        self.assertNotEqual(self.migrate().returncode, 0)
        self.assertEqual(files(self.source), original)

    def test_unsupported_state_or_marker_refused_before_copy(self):
        with sqlite3.connect(self.source / "serverware.sqlite3") as conn:
            conn.execute("CREATE TABLE foreign_provider(secret TEXT)")
            conn.execute("INSERT INTO foreign_provider VALUES ('synthetic')")
        self.assertNotEqual(self.migrate().returncode, 0)
        self.assertEqual(list(self.target.iterdir()), [])
        (self.source / ".serverware-development-sandbox.json").write_text('{"schema":"serverware.operatorDemo/v1"}')
        self.assertNotEqual(self.migrate().returncode, 0)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_bad_audit_and_nonempty_witness_refused(self):
        with sqlite3.connect(self.source / "serverware.sqlite3") as conn:
            conn.execute("UPDATE audit_events SET event_json='{}' WHERE rowid=1")
        self.assertNotEqual(self.migrate().returncode, 0)
        self.assertEqual(list(self.target.iterdir()), [])
        with sqlite3.connect(self.source / "webauthn-recovery-witness.sqlite3") as conn:
            conn.execute("INSERT INTO recovery_witness_heads VALUES ('root','user',1,'time')")
        self.assertNotEqual(self.migrate().returncode, 0)

    def test_bad_policy_leaves_inert_partial_target(self):
        raw = json.loads((self.source / "policy-bundle.json").read_bytes())
        raw["metadata"]["sequence"] = 6
        (self.source / "policy-bundle.json").write_text(json.dumps(raw))
        self.assertNotEqual(self.migrate().returncode, 0)
        self.assertTrue((self.target / "rebrand-incomplete.json").is_file())
        refused = run_worker("reopen", self.target)
        self.assertNotEqual(refused.returncode, 0)

    def test_missing_migrated_authority_is_inert_even_with_dangling_receipt(self):
        result = run_worker("missing-authority", self.target)
        self.assertEqual(result.returncode, 0, result.stderr.decode()[-3500:])

    def test_unknown_auxiliary_or_nonempty_lock_refused_before_copy(self):
        for name, value in (("unreviewed-state.json", b"{}"),
                ("policy-signing-ed25519.pem.lock", b"not empty")):
            path = self.source / name
            previous = path.read_bytes() if path.exists() else None
            path.write_bytes(value)
            path.chmod(0o600)
            before = files(self.source)
            result = self.migrate()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"refused before copying", result.stderr)
            self.assertEqual(list(self.target.iterdir()), [])
            self.assertEqual(files(self.source), before)
            if previous is None:
                path.unlink()
            else:
                path.write_bytes(previous)

    def test_runner_marker_and_symlink_guard(self):
        from catchplate import development_sandbox_runner as runner
        with patch.dict(os.environ, {"CATCHPLATE_DATA_DIR": str(self.target)}, clear=True):
            runner.require_complete_migration()
            marker = self.target / "rebrand-incomplete.json"
            marker.symlink_to(self.target / "absent")
            with self.assertRaisesRegex(RuntimeError, "incomplete Catchplate sandbox migration"):
                runner.main()
        marker.unlink()
        (self.source / "master.key").unlink()
        (self.source / "master.key").symlink_to(self.seed / "master.key")
        self.assertNotEqual(self.migrate().returncode, 0)


if __name__ == "__main__":
    def no_network(event, args):
        if event in {"socket.connect", "socket.getaddrinfo"}:
            raise AssertionError("network forbidden in sandbox migration tests")
    sys.addaudithook(no_network)
    if len(sys.argv) > 1 and sys.argv[1] == "fixture":
        fixture(Path(sys.argv[2]))
    elif len(sys.argv) > 1 and sys.argv[1] == "migrate":
        from catchplate.rebrand_sandbox import migrate
        print(json.dumps(migrate(Path(sys.argv[2]), Path(sys.argv[3]), acknowledge_offline_source=True)))
    elif len(sys.argv) > 1 and sys.argv[1] == "reopen":
        configure(Path(sys.argv[2]))
        from catchplate import development_sandbox_runner as runner
        runner.require_complete_migration()
        from catchplate import development_sandbox as profile, db, crypto
        profile.activate()
        # No reseed, reset, key generation or authority mutation is allowed.
        with patch("catchplate.app.seed_demo", side_effect=AssertionError("must not reseed")):
            profile.bootstrap()
            profile.bootstrap()
        with db.connect() as conn:
            assert crypto.decrypt_secret_envelope(conn.execute("SELECT * FROM credentials").fetchone()) == SECRET
    elif len(sys.argv) > 1 and sys.argv[1] == "missing-authority":
        directory = Path(sys.argv[2])
        configure(directory)
        from catchplate import development_sandbox as profile, development_sandbox_store as store
        from catchplate import policy_bundle as bundles, app
        profile.activate()
        receipt = directory / "rebrand-receipt.json"
        for dangling in (False, True):
            if dangling:
                receipt.symlink_to(directory / "missing-receipt-target")
            else:
                receipt.write_text("{}")
            assert {path.name for path in directory.iterdir()} == {profile.MARKER, receipt.name}
            before = files(directory)
            assert store.get_policy_high_water() is None
            with patch.object(bundles, "sign_policy_bundle", side_effect=AssertionError("must not sign")) as sign, \
                    patch.object(store, "commission_policy", side_effect=AssertionError("must not commission")) as commission, \
                    patch.object(app, "seed_demo", side_effect=AssertionError("must not seed")) as seed:
                for _ in range(2):
                    try:
                        profile.bootstrap()
                    except RuntimeError as error:
                        assert str(error) == "migrated sandbox authority is missing; refusing commissioning or reseed"
                    else:
                        raise AssertionError("missing authority was admitted")
                sign.assert_not_called(); commission.assert_not_called(); seed.assert_not_called()
            assert files(directory) == before
            assert {path.name for path in directory.iterdir()} == {profile.MARKER, receipt.name}
            assert receipt.is_symlink() == dangling
            if dangling:
                assert os.readlink(receipt) == str(directory / "missing-receipt-target")
            assert not (directory / "development-sandbox.sqlite3").exists()
            receipt.unlink()
    else:
        unittest.main()
