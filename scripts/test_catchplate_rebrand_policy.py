#!/usr/bin/env python3
"""Synthetic SQLite + real Ed25519/signature/compiler rebrand checks.

Only the already-held publication lock and deployment settings are fixture
doubles. No daemon, provider, original installation or legacy runtime is used.
"""
from copy import deepcopy
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import config, operator_catalog_policy as policy, operator_catalog_schema as catalog
from catchplate import operator_demo, operator_publication, policy_bundle, rebrand_policy as migration


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


class PolicyMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="catchplate-policy-rebrand-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.target, self.source_gate, self.target_gate = [self.root / value for value in ("source", "target", "old-gate", "new-gate")]
        for path in (self.source, self.target, self.source_gate, self.target_gate):
            path.mkdir(mode=0o700)
        self.key, self.response_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.public = self.key.public_key()
        public = self.public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.key_id = digest(self.public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        for directory in (self.source, self.target):
            for name, data in zip(migration.KEY_FILES, (pem(self.key), public, pem(self.response_key))):
                (directory / name).write_bytes(data)
                (directory / name).chmod(0o644 if name.endswith(".pub.pem") else 0o600)
        self.patches = [patch.object(config, "DATA_DIR", self.target),
            patch.object(policy_bundle, "POLICY_SIGNING_KEY_PATH", self.target / migration.KEY_FILES[0]),
            patch.object(policy_bundle, "POLICY_SIGNING_PUBLIC_KEY_PATH", self.target / migration.KEY_FILES[1]),
            patch.object(operator_publication, "assert_held"),
            patch.object(operator_demo, "settings", return_value={"allowed_upstreams": ["https://api.example.com"], "fixture_cidrs": []})]
        for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo"):
            self.patches.append(patch(target, side_effect=AssertionError("network forbidden")))
        for item in self.patches:
            item.start(); self.addCleanup(item.stop)
        self.old_conn = sqlite3.connect(self.source / "serverware.sqlite3")
        self.new_conn = sqlite3.connect(self.target / "catchplate.sqlite3")
        for conn in (self.old_conn, self.new_conn):
            conn.row_factory = sqlite3.Row
            self.addCleanup(conn.close)
        credential_id, app_id, rule_id = ("00000000-0000-4000-8000-00000000000" + str(index) for index in (1, 2, 3))
        common = {"ordinal": 1, "status": "active", "version": 1}
        self.catalog = {"revision": 9,
            "credentials": [{**common, "id": credential_id, "name": "My serverware secret", "auth_type": "bearer", "header_name": "Authorization", "provider_subject": "retained-subject"}],
            "applications": [{**common, "id": app_id, "name": "Retained client", "principal_id": "agent:operator-demo:" + app_id,
                "token_sha256": "sha256:" + "2" * 64, "token_version": 3, "token_expires_at_epoch_ms": 2000000000000}],
            "access_rules": [{**common, "id": rule_id, "name": "Retained permission", "application_id": app_id, "credential_id": credential_id,
                "route_id": "operator." + rule_id, "upstream_url": "https://api.example.com/serverware-user-path", "methods": ["GET"],
                "request_fields": [], "response_fields": ["status"], "query_keys": [], "allowed_headers": ["accept", "user-agent"]}]}
        self.initial = "sha256:" + "3" * 64
        self.old_policy = policy.render(self.catalog, 7, self.initial)
        self.old_policy["apiVersion"] = "serverware.policy/v1"
        self.old_policy["metadata"]["id"] = migration.LEGACY_POLICY
        self.sign_old()
        self.seed(self.old_conn)
        self.old_conn.backup(self.new_conn)
        self.old_conn.execute("PRAGMA query_only=ON")
        self.new_conn.execute("BEGIN IMMEDIATE")
        self.source_before = self.snapshot(self.source, self.source_gate)

    def sign_old(self):
        self.old_policy["metadata"].pop("signature", None)
        self.old_policy["metadata"]["signingKeyId"] = self.key_id
        self.old_hash = digest(canonical(self.old_policy))
        self.old_policy["metadata"]["signature"] = "ed25519:" + base64.urlsafe_b64encode(self.key.sign(canonical(self.old_policy))).decode().rstrip("=")
        self.old_bytes = canonical(self.old_policy)
        self.old_water = {"api_version": "serverware.policyHighWater/v1", "policy_id": migration.LEGACY_POLICY,
            "sequence": 7, "rollback_epoch": 1, "policy_hash": self.old_hash}
        (self.source / "policy-bundle.json").write_bytes(self.old_bytes)
        (self.source_gate / "policy-high-water.json").write_bytes(canonical(self.old_water) + b"\n")

    def seed(self, conn):
        conn.executescript("""CREATE TABLE operator_demo_policy(singleton INTEGER PRIMARY KEY,sequence INTEGER,policy_hash TEXT,signed_bundle_json TEXT,initial_hash TEXT,updated_at TEXT);
            CREATE TABLE operator_catalog_state(singleton INTEGER PRIMARY KEY,schema_version INTEGER,revision INTEGER);
            INSERT INTO operator_catalog_state VALUES(1,1,9);
            CREATE TABLE operator_catalog_credentials(id TEXT PRIMARY KEY,ordinal INTEGER,data_json TEXT);
            CREATE TABLE operator_catalog_applications(id TEXT PRIMARY KEY,ordinal INTEGER,data_json TEXT);
            CREATE TABLE operator_catalog_rules(id TEXT PRIMARY KEY,application_id TEXT,credential_id TEXT,ordinal INTEGER,data_json TEXT);
            CREATE TABLE credentials(id TEXT PRIMARY KEY,name TEXT,kind TEXT,metadata TEXT,lifecycle_status TEXT);""")
        conn.execute("INSERT INTO operator_demo_policy VALUES(1,7,?,?,?,?)", (self.old_hash, self.old_bytes.decode(), self.initial, "2026-10-01T00:00:00+00:00"))
        for collection, table in catalog._TABLES.items():
            for source in self.catalog[collection]:
                value = deepcopy(source)
                columns = ["id", "ordinal"] if collection != "access_rules" else ["id", "application_id", "credential_id", "ordinal"]
                values = [value.pop(field) for field in columns]
                conn.execute("INSERT INTO " + table + " VALUES(" + ",".join("?" for _ in range(len(values) + 1)) + ")", (*values, canonical(value).decode()))
        credential = self.catalog["credentials"][0]
        conn.execute("INSERT INTO credentials VALUES(?,?,?,?,?)", (credential["id"], credential["name"], "bearer",
            json.dumps({"provider_id": "operator-demo", "provider_subject": credential["provider_subject"], "secret_class": "bearerToken"}), "active"))
        conn.commit()

    def snapshot(self, *roots):
        return {(str(root), str(path.relative_to(root))): path.read_bytes() for root in roots for path in root.rglob("*") if path.is_file()}

    def run_migration(self):
        return migration.prepare_policy_migration(self.old_conn, self.new_conn, self.source, self.target, self.source_gate, self.target_gate)

    def refused(self):
        before = self.snapshot(self.target, self.target_gate)
        rows = list(self.new_conn.iterdump())
        with self.assertRaisesRegex(migration.PolicyMigrationError, "^ordinary policy rebrand refused$"):
            self.run_migration()
        self.assertEqual(rows, list(self.new_conn.iterdump()))
        self.assertEqual(before, self.snapshot(self.target, self.target_gate))

    def test_real_signature_next_sequence_catalog_identity_and_originals(self):
        result = self.run_migration()
        self.assertTrue(self.new_conn.in_transaction, "helper committed caller transaction")
        self.assertEqual(self.snapshot(self.source, self.source_gate), self.source_before)
        current = json.loads((self.target / "policy-bundle.json").read_bytes())
        verified = policy_bundle.compile_policy_bundle(current, verify_signature=True, validate_schema=True)
        self.assertEqual(current["metadata"]["sequence"], 8)
        self.assertEqual(current["principals"], self.old_policy["principals"])
        self.assertEqual(current["routes"], self.old_policy["routes"])
        self.assertEqual(catalog.read_catalog(self.new_conn), self.catalog)
        self.assertEqual(json.loads((self.target_gate / "policy-high-water.json").read_bytes()), result["target"])
        self.assertEqual(result["source"]["policy_hash"], self.old_hash)
        self.assertEqual(result["target"]["policy_hash"], verified.hash)
        archive = self.target / "rebrand-originals"
        self.assertEqual((archive / "policy-bundle.json").read_bytes(), self.old_bytes)
        receipt_signature = result.pop("signature").removeprefix("ed25519:")
        self.public.verify(base64.urlsafe_b64decode(receipt_signature + "=="), migration.LINEAGE.encode() + b"\0" + canonical(result))
        self.refused()  # A second invocation cannot reset high-water or republish.

    def test_invalid_old_signature_refused(self):
        changed = self.old_bytes.decode().replace('"GET"', '"PUT"')
        self.old_conn.execute("PRAGMA query_only=OFF")
        self.old_conn.execute("UPDATE operator_demo_policy SET signed_bundle_json=?", (changed,)); self.old_conn.commit()
        self.old_conn.execute("PRAGMA query_only=ON")
        self.new_conn.execute("UPDATE operator_demo_policy SET signed_bundle_json=?", (changed,))
        self.refused()

    def test_empty_policy_and_copied_highwater_remain_deny_all(self):
        self.old_conn.execute("PRAGMA query_only=OFF")
        for conn in (self.old_conn, self.new_conn):
            for table in (*catalog._TABLES.values(), "credentials"):
                conn.execute("DELETE FROM " + table)
        self.catalog = {"revision": 9, "credentials": [], "applications": [], "access_rules": []}
        self.old_policy = policy.render(self.catalog, 7, self.initial)
        self.old_policy["apiVersion"] = "serverware.policy/v1"
        self.old_policy["metadata"]["id"] = migration.LEGACY_POLICY
        self.old_policy["routes"][0]["match"]["paths"] = ["/__serverware_operator_demo_unconfigured__"]
        self.sign_old()
        for conn in (self.old_conn, self.new_conn):
            conn.execute("UPDATE operator_demo_policy SET policy_hash=?,signed_bundle_json=?", (self.old_hash, self.old_bytes.decode()))
        self.old_conn.commit(); self.old_conn.execute("PRAGMA query_only=ON")
        (self.target_gate / "policy-high-water.json").write_bytes((self.source_gate / "policy-high-water.json").read_bytes())
        result = self.run_migration()
        current = json.loads((self.target / "policy-bundle.json").read_bytes())
        self.assertEqual(current["principals"], self.old_policy["principals"])
        self.assertEqual(current["principals"][0]["proxyAuthorization"]["expiresAtEpochMs"], 1)
        self.assertEqual(current["credentials"], [])
        self.assertEqual(current["routes"][0]["match"]["paths"], ["/__catchplate_operator_demo_unconfigured__"])
        self.assertEqual(result["target"]["sequence"], 8)

    def test_highwater_rollback_id_hash_and_bool_refused(self):
        for field, value in (("api_version", "catchplate.policyHighWater/v1"), ("policy_id", migration.CURRENT_POLICY),
                ("sequence", 6), ("rollback_epoch", True), ("policy_hash", "sha256:" + "f" * 64)):
            with self.subTest(field=field):
                (self.source_gate / "policy-high-water.json").write_bytes(canonical({**self.old_water, field: value}))
                self.refused()

    def test_catalog_token_and_scope_drift_refused(self):
        for table, field, value in (("operator_catalog_applications", "token_sha256", "sha256:" + "4" * 64),
                ("operator_catalog_rules", "upstream_url", "https://api.example.com/wider")):
            old = self.new_conn.execute("SELECT data_json FROM " + table).fetchone()[0]
            data = json.loads(old); data[field] = value
            self.new_conn.execute("UPDATE " + table + " SET data_json=?", (json.dumps(data),))
            self.refused()
            self.new_conn.execute("UPDATE " + table + " SET data_json=?", (old,))

    def test_key_rotation_duplicate_json_and_link_refused(self):
        key = self.target / migration.KEY_FILES[0]
        original = key.read_bytes(); key.write_bytes(pem(Ed25519PrivateKey.generate()))
        self.refused(); key.write_bytes(original)
        water = self.source_gate / "policy-high-water.json"
        water.write_bytes(canonical(self.old_water)[:-1] + b',"sequence":7}')
        self.refused(); water.write_bytes(canonical(self.old_water))
        destination = self.target_gate / "policy-high-water.json"
        destination.symlink_to(water)
        self.refused()

    def test_source_readonly_transaction_and_target_water_guards(self):
        self.old_conn.execute("PRAGMA query_only=OFF")
        self.refused(); self.old_conn.execute("PRAGMA query_only=ON")
        self.new_conn.commit(); self.refused(); self.new_conn.execute("BEGIN IMMEDIATE")
        (self.target_gate / "policy-high-water.json").write_bytes(canonical({**self.old_water, "sequence": 99}))
        self.refused()

    def test_closed_protocol_differences_and_user_strings(self):
        migration._protocol_only({"schema": "serverware.hostTrustedApprovalPolicy/v1"}, {"schema": "catchplate.hostTrustedApprovalPolicy/v1"})
        migration._protocol_only("Bearer serverware-openai-placeholder-v1", "Bearer catchplate-openai-placeholder-v1", ("routes", 0, "credentialHeader", "expectedValue"))
        for old, new, path in (("serverware-user", "catchplate-user", ("metadata", "name")),
                ("serverware.custom/v1", "catchplate.custom/v2", ("schema",)),
                ("Bearer serverware-custom-key", "Bearer catchplate-custom-key", ("routes", 0, "credentialHeader", "expectedValue")),
                (True, 1, ("metadata", "sequence"))):
            with self.assertRaises(migration.PolicyMigrationError):
                migration._protocol_only(old, new, path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
