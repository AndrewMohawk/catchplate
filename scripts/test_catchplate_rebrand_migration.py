#!/usr/bin/env python3
"""Focused synthetic migration checks; no provider calls or live state."""
from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
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
SECRET = "synthetic-rebrand-secret-serverware-must-stay-in-plaintext"


def old_envelope(row, master, secret):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    encode = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
    dek, dn, sn = os.urandom(32), os.urandom(12), os.urandom(12)
    binding = f'{row["id"]}:v{row["credential_version"]}'
    return {"encrypted_dek": "v1:" + encode(dn) + ":" + encode(AESGCM(master).encrypt(dn, dek, ("serverware:dek:" + binding).encode())),
        "secret_nonce": "v1:" + encode(sn),
        "secret_ciphertext": "v1:" + encode(AESGCM(dek).encrypt(sn, secret.encode(), ("serverware:secret:" + binding).encode()))}


def prepare_fixture(source, gate):
    os.umask(0o077)
    import test_operator_demo_persistence as common
    import test_operator_workspace_store as workspace
    os.environ.update(common._ENVIRONMENT)
    os.environ["CATCHPLATE_DATA_DIR"] = str(source)
    config, db, store, bundles, schema, _ = workspace.legacy_fixture(with_revocation=False)
    workspace.migrate(db, schema)
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
    from cryptography.x509.oid import NameOID
    response = ed25519.Ed25519PrivateKey.generate()
    (source / "response-signing-ed25519.pem").write_bytes(response.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Serverware CA")])
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key()).serial_number(1).not_valid_before(
        now - timedelta(days=1)).not_valid_after(now + timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca_key, hashes.SHA256())
    ca = source / "mitmproxy"
    ca.mkdir(mode=0o700, exist_ok=True)
    (ca / "mitmproxy-ca.pem").write_bytes(ca_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()) + cert.public_bytes(serialization.Encoding.PEM))
    (ca / "mitmproxy-ca-cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    with db.connect() as conn:
        conn.row_factory = sqlite3.Row
        from catchplate import operator_x_quota as quota
        for sql in quota._DDL.values():
            conn.execute(sql)
        event = db.append_audit_event(conn, event_type=quota.INITIALIZED, actor_type="system",
            actor_id=None, event={"schema": "serverware.operatorXPostingQuotaStore/v1", "initialized_at_epoch_ms": 1000})
        conn.execute("INSERT INTO operator_x_quota_state VALUES (1,1,?,?,1000,1000)", (event["id"], event["event_hash"]))
        master = (source / "master.key").read_bytes()
        for row in conn.execute("SELECT * FROM credentials"):
            envelope = old_envelope(dict(row), master, SECRET)
            conn.execute("UPDATE credentials SET encrypted_dek=?,secret_nonce=?,secret_ciphertext=? WHERE id=?",
                (*envelope.values(), row["id"]))
        retained = dict(conn.execute("SELECT * FROM operator_demo_policy").fetchone())
        policy = json.loads(retained["signed_bundle_json"])
        policy["apiVersion"] = "serverware.policy/v1"
        policy["metadata"]["id"] = "serverware-operator-demo"
        policy["metadata"].pop("signature")
        policy = bundles.sign_policy_bundle(policy)
        unsigned = deepcopy(policy)
        unsigned["metadata"].pop("signature")
        raw = bundles.canonical_json(policy)
        policy_hash = "sha256:" + hashlib.sha256(bundles.canonical_json(unsigned).encode()).hexdigest()
        conn.execute("UPDATE operator_demo_policy SET signed_bundle_json=?,policy_hash=?", (raw, policy_hash))
        conn.execute("ALTER TABLE catchplate_store_migrations RENAME TO serverware_store_migrations")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    (source / "policy-bundle.json").write_text(raw)
    (gate / "policy-high-water.json").write_text(json.dumps({"api_version": "serverware.policyHighWater/v1",
        "policy_id": "serverware-operator-demo", "sequence": retained["sequence"], "rollback_epoch": 1, "policy_hash": policy_hash}))
    (source / "catchplate.sqlite3").rename(source / "serverware.sqlite3")
    (source / ".catchplate-operator-demo.json").rename(source / ".serverware-operator-demo.json")
    (source / ".serverware-operator-demo.json").write_bytes(b'{"schema": "serverware.operatorDemo/v1", "syntheticOnly": false}\n')
    for directory in (source, gate):
        for path in directory.rglob("*"):
            if path.is_file():
                path.chmod(0o644 if path.name.endswith((".pub.pem", "-cert.pem")) else 0o600)
    return {"prepared": True}


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="catchplate-rebrand-")
        self.root = Path(self.temp.name)
        self.source, self.gate, self.target, self.target_gate = [self.root / name for name in ("source", "gate", "target", "target-gate")]
        for path in (self.source, self.gate, self.target, self.target_gate):
            path.mkdir(mode=0o700)

    def tearDown(self):
        self.temp.cleanup()

    def worker(self, *args):
        env = {key: value for key, value in os.environ.items() if not key.startswith(("CATCHPLATE_", "SERVERWARE_"))}
        return subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), *map(str, args)],
            cwd=ROOT, env=env, capture_output=True, timeout=60)

    def seed(self):
        result = self.worker("fixture", self.source, self.gate)
        self.assertEqual(result.returncode, 0, result.stderr.decode()[-2500:])

    def migrate(self):
        return self.worker("migrate", self.source, self.target, self.gate, self.target_gate)

    def test_complete_copy_preserves_history_identity_ca_and_secret_semantics(self):
        self.seed()
        snapshot = {str(p.relative_to(self.source)): p.read_bytes() for p in self.source.rglob("*") if p.is_file()}
        result = self.migrate()
        self.assertEqual(result.returncode, 0, result.stderr.decode()[-4000:])
        self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)
        self.assertEqual(snapshot, {str(p.relative_to(self.source)): p.read_bytes() for p in self.source.rglob("*") if p.is_file()})
        receipt = json.loads((self.target / "rebrand-receipt.json").read_bytes())
        self.assertEqual(receipt["rewrapped_credentials"], 2)
        self.assertEqual((self.target / "master.key").read_bytes(), (self.source / "master.key").read_bytes())
        self.assertEqual((self.target / "mitmproxy/mitmproxy-ca.pem").read_bytes(), (self.source / "mitmproxy/mitmproxy-ca.pem").read_bytes())
        self.assertFalse((self.target / "rebrand-incomplete.json").exists())
        old = sqlite3.connect(self.source / "serverware.sqlite3")
        new = sqlite3.connect(self.target / "catchplate.sqlite3")
        for table in ("credential_generations", "operator_catalog_applications", "operator_demo_connections"):
            self.assertEqual(old.execute("SELECT * FROM " + table).fetchall(), new.execute("SELECT * FROM " + table).fetchall())
        audits = old.execute("SELECT * FROM audit_events ORDER BY rowid").fetchall()
        self.assertEqual(audits, new.execute("SELECT * FROM audit_events ORDER BY rowid LIMIT ?", (len(audits),)).fetchall())
        self.assertEqual(new.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], len(audits) + 1)
        old.close(); new.close()
        repeated = self.migrate()
        self.assertNotEqual(repeated.returncode, 0)

    def test_unknown_populated_table_refused_before_target_writes(self):
        self.seed()
        with sqlite3.connect(self.source / "serverware.sqlite3") as conn:
            conn.execute("CREATE TABLE unexpected_provider(secret TEXT)")
            conn.execute("INSERT INTO unexpected_provider VALUES ('synthetic-unsupported')")
        result = self.migrate()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_audit_corruption_refused_before_target_writes(self):
        self.seed()
        with sqlite3.connect(self.source / "serverware.sqlite3") as conn:
            conn.execute("UPDATE audit_events SET event_json='{}' WHERE rowid=1")
        result = self.migrate()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.target.iterdir()), [])

    def test_only_exact_generated_placeholders_change(self):
        from catchplate.rebrand_migration import migrate_rule
        for marker in ({"app_preset": "openai"}, {"operation_bundle": "github_issues_read_v1"}):
            old = {"data_json": json.dumps({**marker, "name": "serverware user title", "placeholder": "Bearer serverware-openai-placeholder-v1"})}
            changed = json.loads(migrate_rule(old)["data_json"])
            self.assertEqual(changed["placeholder"], "Bearer catchplate-openai-placeholder-v1")
            self.assertEqual(changed["name"], "serverware user title")
        custom = {"data_json": json.dumps({"placeholder": "Bearer serverware-openai-placeholder-v1"})}
        self.assertEqual(migrate_rule(custom), custom)

    def test_incomplete_migration_refuses_runner_before_importing_application(self):
        from catchplate import operator_demo_runner
        from scripts.operator_install import runtime
        marker = self.target / "rebrand-incomplete.json"
        with patch.dict(os.environ, {"CATCHPLATE_DATA_DIR": str(self.target)}, clear=True):
            operator_demo_runner.require_complete_migration()
            runtime.require_complete_migration(self.target)
            marker.write_text("{}")
            with self.assertRaisesRegex(RuntimeError, "incomplete Catchplate migration"):
                operator_demo_runner.main()
            with self.assertRaises(ValueError):
                runtime.require_complete_migration(self.target)
            with patch.dict(os.environ, {"CATCHPLATE_POLICY_HIGH_WATER_FILE": str(self.target / "policy-high-water.json")}), \
                    patch.object(sys, "argv", ["runtime", "gate"]), \
                    patch.object(runtime, "artifact", side_effect=AssertionError("artifact must not load")), \
                    self.assertRaises(ValueError):
                runtime.main()
            marker.unlink()
            marker.symlink_to(self.target / "missing")
            with self.assertRaisesRegex(RuntimeError, "incomplete Catchplate migration"):
                operator_demo_runner.main()
            with self.assertRaises(ValueError):
                runtime.require_complete_migration(self.target)


if __name__ == "__main__":
    def refuse_network(event, args):
        if event in {"socket.connect", "socket.getaddrinfo"}:
            raise AssertionError("network forbidden in synthetic migration checks")
    sys.addaudithook(refuse_network)
    if len(sys.argv) > 1 and sys.argv[1] == "fixture":
        print(json.dumps(prepare_fixture(Path(sys.argv[2]), Path(sys.argv[3]))))
    elif len(sys.argv) > 1 and sys.argv[1] == "migrate":
        from catchplate.rebrand_migration import migrate
        result = migrate(*map(Path, sys.argv[2:6]), public_url="https://console.example.com", proxy_url="https://proxy.example.com",
            acknowledge_offline_source=True)
        from catchplate import crypto, config
        with sqlite3.connect(config.DB_PATH) as connection:
            connection.row_factory = sqlite3.Row
            assert all(crypto.decrypt_secret_envelope(row) == SECRET for row in connection.execute("SELECT * FROM credentials"))
        print(json.dumps(result))
    else:
        unittest.main()
