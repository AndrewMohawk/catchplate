#!/usr/bin/env python3
"""Offline actual-AES and private SQLite custody controls, not activation.

Positive writer component tests substitute only the publication ownership
assertion. Transactions, retained schemas, encryption and rollback are real;
these tests do not claim an admitted operator lifecycle or publication lock.
"""
from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from catchplate import operator_provider_custody as google
from catchplate import operator_x_oauth_profile as profile
from catchplate import operator_x_provider_custody as custody

KEY = bytes(range(32))
SECRET = "synthetic-X-application-secret-only"
OWNER_ID = "12345678-1234-4234-8234-123456789abc"


def no_network(event, _args):
    if event.startswith(("socket.", "subprocess.")):
        raise AssertionError("network and child processes forbidden in custody tests")


sys.addaudithook(no_network)


def owner(identifier=OWNER_ID):
    return google.admit_development_owner(identifier, operator_development=True,
        release_channel="dev", production_image=False, native_or_enrolled=False)


def binding(admitted, version=1, client="synthetic-X-client", origin="https://console.example.com"):
    return custody.bind_x(admitted, config_version=version,
        public_profile=profile.public_record(profile.build_profile(client_id=client, public_origin=origin)))


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.owner = owner()
        self.binding = binding(self.owner)

    def refused(self, function, *args, **kwargs):
        with self.assertRaises(custody.CustodyError) as caught:
            function(*args, **kwargs)
        self.assertEqual(str(caught.exception), "operator X provider custody refused")
        self.assertNotIn(SECRET, repr(caught.exception))

    def seal(self):
        return custody.seal_x(self.owner, self.binding, key=KEY, secret=SECRET)

    def test_actual_aes_roundtrip_redacted_material_and_fresh_nonce(self):
        envelope = self.seal()
        material = custody.open_x(self.owner, envelope, key=KEY)
        self.assertEqual(material.secret, SECRET)
        self.assertNotIn(SECRET, repr(material))
        self.assertNotIn(repr(envelope.nonce), repr(envelope))
        self.assertNotIn(repr(envelope.ciphertext), repr(envelope))
        self.assertNotEqual(envelope.nonce, self.seal().nonce)
        expected = {"schema": "catchplate.operatorXProviderCustody/v1", "owner_id": OWNER_ID,
            "config_version": 1, "public_profile": json.loads(self.binding.profile_json), "secret_present": True}
        self.assertEqual(material.public_view(), expected)
        material.public_view()["public_profile"]["scopes"].append("other")
        self.assertEqual(material.public_view(), expected)
        self.assertNotIn(SECRET, json.dumps(expected))

    def test_independently_constructed_aad_matches_real_ciphertext(self):
        envelope = self.seal()
        aad = {"schema": "catchplate.operatorXProviderCustodyAAD/v1", "owner_id": OWNER_ID,
            "config_version": 1, "public_profile": json.loads(self.binding.profile_json)}
        raw = json.dumps(aad, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self.assertEqual(AESGCM(KEY).decrypt(envelope.nonce, envelope.ciphertext, raw), SECRET.encode())
        nonce = b"n" * 12
        independent = custody.XPrivateEnvelope(self.binding, nonce, AESGCM(KEY).encrypt(nonce, SECRET.encode(), raw))
        self.assertEqual(custody.open_x(self.owner, independent, key=KEY).secret, SECRET)

    def test_owner_version_client_and_callback_substitution_refused(self):
        envelope = self.seal()
        other = owner("22345678-1234-4234-8234-123456789abc")
        for admitted, changed in ((other, binding(other)), (self.owner, binding(self.owner, version=2)),
                (self.owner, binding(self.owner, client="different-client")),
                (self.owner, binding(self.owner, origin="https://other.example.com"))):
            self.refused(custody.open_x, admitted, replace(envelope, binding=changed), key=KEY)

    def test_google_and_x_are_distinct_types_and_aad_domains(self):
        public = google.google._record("123-synthetic.apps.googleusercontent.com",
            "https://console.example.com/api/oauth/callback/google")
        old_binding = google.bind_google(self.owner, config_version=1, public_profile=public)
        old_envelope = google.seal(self.owner, old_binding, key=KEY, secret=SECRET)
        self.refused(custody.bind_x, self.owner, config_version=1, public_profile=public)
        self.refused(custody.seal_x, self.owner, old_binding, key=KEY, secret=SECRET)
        self.refused(custody.open_x, self.owner, old_envelope, key=KEY)
        x_envelope = self.seal()
        self.refused(custody.open_x, self.owner,
            custody.XPrivateEnvelope(self.binding, old_envelope.nonce, old_envelope.ciphertext), key=KEY)
        with self.assertRaises(google.CustodyError):
            google.open_secret(self.owner,
                google.PrivateEnvelope(old_binding, x_envelope.nonce, x_envelope.ciphertext), key=KEY)
        self.assertEqual(google.open_secret(self.owner, old_envelope, key=KEY).secret, SECRET)

    def test_current_exact_owner_and_bounded_version_required(self):
        record = json.loads(self.binding.profile_json)
        for admitted in (None, replace(self.owner, uid=os.geteuid() + 1), replace(self.owner, pid=os.getpid() + 1),
                replace(self.owner, uid=True), replace(self.owner, owner_id="not-a-uuid")):
            self.refused(custody.bind_x, admitted, config_version=1, public_profile=record)
        for version in (0, 17, True, 1.0, "1", None):
            self.refused(custody.bind_x, self.owner, config_version=version, public_profile=record)
        self.assertEqual(binding(self.owner, version=16).config_version, 16)

    def test_malformed_key_envelope_and_modified_ciphertext_refused(self):
        envelope = self.seal()
        for key in (None, b"k" * 31, b"k" * 33, bytearray(KEY), "k" * 32):
            self.refused(custody.seal_x, self.owner, self.binding, key=key, secret=SECRET)
            self.refused(custody.open_x, self.owner, envelope, key=key)
        for changed in (replace(envelope, nonce=b"n" * 11), replace(envelope, nonce=bytearray(envelope.nonce)),
                replace(envelope, ciphertext=b"x" * 16), replace(envelope, ciphertext=b"x" * 4113),
                replace(envelope, ciphertext=envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1]))):
            self.refused(custody.open_x, self.owner, changed, key=KEY)
        self.refused(custody.open_x, self.owner, envelope, key=b"x" * 32)

    def test_canonical_binding_and_closed_profile_are_revalidated(self):
        for raw in (self.binding.profile_json + " ", "{}", "x" * 4097,
                self.binding.profile_json.replace('"provider_id":"x"', '"provider_id":"x","provider_id":"x"'),
                self.binding.profile_json.replace("tweet.write", "tweet.delete")):
            self.refused(custody.seal_x, self.owner, replace(self.binding, profile_json=raw), key=KEY, secret=SECRET)
        self.refused(custody.seal_x, self.owner, replace(self.binding, owner_id="other"), key=KEY, secret=SECRET)

    def test_plaintext_bounds_and_authenticated_bad_plaintext_refuse(self):
        for secret in ("x" * 4096, "é" * 2048):
            envelope = custody.seal_x(self.owner, self.binding, key=KEY, secret=secret)
            self.assertEqual(custody.open_x(self.owner, envelope, key=KEY).secret, secret)
        for secret in ("", "x" * 4097, "é" * 2049, SECRET + "\n", "\ud800", None):
            self.refused(custody.seal_x, self.owner, self.binding, key=KEY, secret=secret)
        aad = json.dumps({"schema": "catchplate.operatorXProviderCustodyAAD/v1", "owner_id": OWNER_ID,
            "config_version": 1, "public_profile": json.loads(self.binding.profile_json)},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        for raw in (b"\xff", b"x\x00", b" x", b"x\n"):
            nonce = b"n" * 12
            envelope = custody.XPrivateEnvelope(self.binding, nonce, AESGCM(KEY).encrypt(nonce, raw, aad))
            self.refused(custody.open_x, self.owner, envelope, key=KEY)

    def test_no_runtime_key_or_activation_api_is_exposed(self):
        self.seal()
        for name in ("catchplate.config", "catchplate.db", "catchplate.oauth", "catchplate.operator_provider_key"):
            self.assertNotIn(name, sys.modules)
        for name in ("initialize_first", "read_existing_master_key", "activate", "require_profile"):
            self.assertFalse(hasattr(custody, name))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.owner = owner()
        self.binding = binding(self.owner)
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.execute("BEGIN IMMEDIATE")

    def refused(self, function, *args, absent=False, **kwargs):
        error = custody.CustodyAbsent if absent else custody.CustodyError
        with self.assertRaises(error) as caught:
            function(*args, **kwargs)
        expected = "operator X provider custody absent" if absent else "operator X provider custody refused"
        self.assertEqual(str(caught.exception), expected)
        self.assertNotIn(SECRET, repr(caught.exception))

    def install(self, conn=None):
        with patch("catchplate.operator_publication.assert_held") as held:
            custody.install_empty_store(conn if conn is not None else self.conn, self.owner)
        held.assert_called_once_with()

    def insert(self, selected=None, conn=None, secret=SECRET):
        with patch("catchplate.operator_publication.assert_held") as held:
            custody.insert_secret(conn if conn is not None else self.conn, self.owner,
                selected if selected is not None else self.binding, key=KEY, secret=secret)
        held.assert_called_once_with()

    def inspect(self):
        return custody.inspect_public_binding(self.conn, self.owner, self.binding)

    def test_real_transaction_and_unheld_publication_refuse_before_write(self):
        before = tuple(self.conn.iterdump())
        self.refused(custody.install_empty_store, self.conn, self.owner)
        self.assertEqual(tuple(self.conn.iterdump()), before)
        self.conn.rollback()
        with patch("catchplate.operator_publication.assert_held") as held:
            self.refused(custody.install_empty_store, self.conn, self.owner)
        held.assert_not_called()
        self.refused(custody.inspect_public_binding, self.conn, self.owner, self.binding)
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY)
        self.refused(custody.install_empty_store, object(), self.owner)

    def test_no_implicit_install_and_full_caller_rollback(self):
        before = tuple(self.conn.iterdump())
        self.refused(custody.inspect_public_binding, self.conn, self.owner, self.binding, absent=True)
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY, absent=True)
        with patch("catchplate.operator_publication.assert_held"):
            self.refused(custody.insert_secret, self.conn, self.owner, self.binding, key=KEY, secret=SECRET, absent=True)
        self.assertEqual(tuple(self.conn.iterdump()), before)
        self.install()
        self.insert()
        self.assertTrue(self.conn.in_transaction)
        self.assertEqual(custody.read_secret(self.conn, self.owner, self.binding, key=KEY).secret, SECRET)
        self.assertNotIn(SECRET, "\n".join(self.conn.iterdump()))
        # The lifecycle's later audit failure is part of the same real txn.
        self.conn.execute("CREATE TABLE caller_audit(value TEXT CHECK(value='accepted'))")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO caller_audit VALUES('refused')")
        self.conn.rollback()
        self.conn.execute("BEGIN")
        self.refused(custody.inspect_public_binding, self.conn, self.owner, self.binding, absent=True)
        self.assertEqual(tuple(self.conn.iterdump()), before)

    def test_actual_wal_commit_visibility_and_cold_read_only_reopen(self):
        with tempfile.TemporaryDirectory(prefix="x-custody-unit-") as temporary:
            path = Path(temporary) / "private.sqlite3"
            writer = sqlite3.connect(path)
            observer = sqlite3.connect(path)
            try:
                self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
                writer.execute("BEGIN IMMEDIATE")
                self.install(writer)
                self.insert(conn=writer)
                self.assertTrue(writer.in_transaction)
                self.assertIsNone(observer.execute("SELECT name FROM sqlite_master WHERE name=?", (custody.TABLE,)).fetchone())
                writer.commit()
                self.assertEqual(observer.execute(f"SELECT count(*) FROM {custody.TABLE}").fetchone()[0], 1)
            finally:
                observer.close()
                writer.close()
            cold = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
            try:
                cold.execute("PRAGMA query_only=ON")
                cold.execute("BEGIN")
                self.assertEqual(custody.read_secret(cold, self.owner, self.binding, key=KEY).secret, SECRET)
                self.assertTrue(custody.inspect_public_binding(cold, self.owner, self.binding)["secret_present"])
                self.assertTrue(cold.in_transaction)
                cold.rollback()
                self.assertEqual(cold.execute("SELECT 1").fetchone()[0], 1)
            finally:
                cold.close()

    def test_immutable_rows_and_no_duplicate_or_replace(self):
        self.install()
        self.insert()
        before = tuple(self.conn.iterdump())
        with patch("catchplate.operator_publication.assert_held"):
            self.refused(custody.install_empty_store, self.conn, self.owner)
            self.refused(custody.insert_secret, self.conn, self.owner, self.binding, key=KEY, secret="replacement")
        for table in (custody.TABLE, custody.META):
            for sql in (f"DELETE FROM {table}", f"UPDATE {table} SET {('config_version' if table == custody.TABLE else 'singleton')}=2",
                    f"INSERT OR REPLACE INTO {table} SELECT * FROM {table}"):
                with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                    self.conn.execute(sql)
        self.assertEqual(tuple(self.conn.iterdump()), before)
        self.assertTrue(self.conn.in_transaction)

    def test_exact_version_owner_profile_without_latest_fallback(self):
        self.install()
        selected = binding(self.owner, version=2)
        self.insert(selected)
        other = owner("22345678-1234-4234-8234-123456789abc")
        for admitted, candidate in ((self.owner, self.binding), (other, binding(other, version=2)),
                (self.owner, binding(self.owner, version=2, client="other-client")),
                (self.owner, binding(self.owner, version=2, origin="https://other.example.com"))):
            self.refused(custody.inspect_public_binding, self.conn, admitted, candidate)
            self.refused(custody.read_secret, self.conn, admitted, candidate, key=KEY)
        self.assertEqual(custody.read_secret(self.conn, self.owner, selected, key=KEY).secret, SECRET)

    def test_sixteen_versions_and_query_only_public_views_never_decrypt(self):
        self.install()
        for version in range(1, 17):
            self.insert(binding(self.owner, version=version))
        before = tuple(self.conn.iterdump())
        self.conn.commit()
        self.conn.execute("PRAGMA query_only=ON")
        self.conn.execute("BEGIN")
        with patch.object(custody, "_key", side_effect=AssertionError("key touched")), \
                patch.object(custody, "open_x", side_effect=AssertionError("secret touched")), \
                patch.object(custody, "AESGCM", side_effect=AssertionError("cipher touched")), \
                patch("catchplate.operator_publication.assert_held", side_effect=AssertionError("writer touched")):
            public = self.inspect()
        self.assertEqual(public["config_version"], 1)
        self.assertNotIn(SECRET, json.dumps(public))
        public["public_profile"]["scopes"].clear()
        self.assertEqual(self.inspect()["public_profile"]["scopes"], list(profile.SCOPES))
        self.assertEqual(tuple(self.conn.iterdump()), before)
        with patch("catchplate.operator_publication.assert_held"):
            self.refused(custody.insert_secret, self.conn, self.owner, self.binding, key=KEY, secret=SECRET)

    def test_all_unselected_rows_are_bounded_and_structurally_validated(self):
        self.install()
        self.insert()
        duplicate = self.binding.profile_json[:-1] + ',"client_id":"synthetic-X-client"}'
        cases = ((self.binding.profile_json, b"n" * 11, b"x" * 32),
            (self.binding.profile_json, "n" * 12, b"x" * 32),
            (self.binding.profile_json, b"n" * 12, b"x" * 16),
            (self.binding.profile_json, b"n" * 12, b"x" * 4113),
            (self.binding.profile_json, b"n" * 12, "x" * 32),
            ("{}", b"n" * 12, b"x" * 32), ("x" * 4097, b"n" * 12, b"x" * 32),
            (duplicate, b"n" * 12, b"x" * 32))
        for index, values in enumerate(cases):
            with self.subTest(case=index):
                self.conn.execute("SAVEPOINT malformed")
                self.conn.execute(f"INSERT INTO {custody.TABLE} VALUES(?,?,?,?)", (2, *values))
                self.refused(custody.inspect_public_binding, self.conn, self.owner, self.binding)
                self.conn.execute("ROLLBACK TO malformed")
                self.conn.execute("RELEASE malformed")
        self.assertTrue(self.inspect()["secret_present"])

    def test_namespace_drift_and_temp_shadow_are_not_absence(self):
        for sql in ("CREATE TABLE Operator_X_Provider_Custody(extra TEXT)",
                "CREATE TABLE operator_x_provider_custody_orphan(extra TEXT)",
                "CREATE TEMP TABLE operator_x_provider_custody(extra TEXT)"):
            with self.subTest(sql=sql):
                self.conn.execute("SAVEPOINT malformed")
                self.conn.execute(sql)
                before = tuple(self.conn.iterdump())
                self.refused(custody.inspect_public_binding, self.conn, self.owner, self.binding)
                with patch("catchplate.operator_publication.assert_held"):
                    self.refused(custody.install_empty_store, self.conn, self.owner)
                self.assertEqual(tuple(self.conn.iterdump()), before)
                self.conn.execute("ROLLBACK TO malformed")
                self.conn.execute("RELEASE malformed")
        self.install()
        self.insert()
        for sql in (f"DROP TRIGGER {custody.TABLE}_retained",
                f"CREATE INDEX unrelated_name ON {custody.TABLE}(profile_json)",
                f"CREATE TEMP TABLE {custody.TABLE}(extra TEXT)"):
            self.conn.execute("SAVEPOINT malformed")
            self.conn.execute(sql)
            self.refused(custody.inspect_public_binding, self.conn, self.owner, self.binding)
            self.conn.execute("ROLLBACK TO malformed")
            self.conn.execute("RELEASE malformed")

    def test_marker_owner_schema_type_and_size_must_match(self):
        self.install()
        self.insert()
        trigger = next(sql for name, _, _, sql in custody._DEFINITIONS if name == custody.META + "_immutable")
        for schema, owner_id in ((custody.SCHEMA + "x" * 9000, OWNER_ID), (custody.SCHEMA, "x" * 9000),
                (custody.SCHEMA.encode(), OWNER_ID), (custody.SCHEMA, "22345678-1234-4234-8234-123456789abc")):
            self.conn.execute("SAVEPOINT malformed")
            self.conn.execute(f"DROP TRIGGER {custody.META}_immutable")
            self.conn.execute(f"UPDATE {custody.META} SET schema=?,owner_id=?", (schema, owner_id))
            self.conn.execute(trigger)
            self.refused(custody.inspect_public_binding, self.conn, self.owner, self.binding)
            self.conn.execute("ROLLBACK TO malformed")
            self.conn.execute("RELEASE malformed")

    def test_google_store_and_x_store_coexist_without_cross_adoption(self):
        google_binding = google.bind_google(self.owner, config_version=1,
            public_profile=google.google._record("123-synthetic.apps.googleusercontent.com",
                "https://console.example.com/api/oauth/callback/google"))
        with patch("catchplate.operator_publication.assert_held"):
            google.install_empty_store(self.conn, self.owner)
            google.insert_secret(self.conn, self.owner, google_binding, key=KEY, secret="synthetic-Google-secret")
        google_before = tuple(self.conn.execute(f"SELECT * FROM {google.TABLE}"))
        self.install()
        self.insert()
        self.assertEqual(tuple(self.conn.execute(f"SELECT * FROM {google.TABLE}")), google_before)
        self.assertEqual(google.read_secret(self.conn, self.owner, google_binding, key=KEY).secret, "synthetic-Google-secret")
        self.assertEqual(custody.read_secret(self.conn, self.owner, self.binding, key=KEY).secret, SECRET)
        self.refused(custody.read_secret, self.conn, self.owner, google_binding, key=KEY)
        with self.assertRaises(google.CustodyError):
            google.read_secret(self.conn, self.owner, self.binding, key=KEY)

    def test_structural_presence_does_not_claim_ciphertext_authenticity(self):
        self.install()
        self.conn.execute(f"INSERT INTO {custody.TABLE} VALUES(?,?,?,?)",
            (1, self.binding.profile_json, b"n" * 12, b"x" * 32))
        self.assertTrue(self.inspect()["secret_present"])
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY)

    def test_query_only_dirty_read_and_closed_connections_refuse_writes(self):
        self.conn.execute("PRAGMA query_only=ON")
        with patch("catchplate.operator_publication.assert_held"):
            self.refused(custody.install_empty_store, self.conn, self.owner)
        self.conn.execute("PRAGMA query_only=OFF")
        self.conn.execute("PRAGMA read_uncommitted=ON")
        with patch("catchplate.operator_publication.assert_held") as held:
            self.refused(custody.install_empty_store, self.conn, self.owner)
        held.assert_not_called()
        self.refused(custody.inspect_public_binding, self.conn, self.owner, self.binding)
        self.conn.close()
        self.refused(custody.inspect_public_binding, self.conn, self.owner, self.binding)
        with patch("catchplate.operator_publication.assert_held") as held:
            self.refused(custody.install_empty_store, self.conn, self.owner)
        held.assert_not_called()

    def test_roster_absence_empty_and_caller_snapshot_are_distinct(self):
        before = tuple(self.conn.iterdump())
        self.refused(custody.inspect_public_roster, self.conn, self.owner, absent=True)
        self.assertEqual(tuple(self.conn.iterdump()), before)
        self.install()
        self.assertEqual(custody.inspect_public_roster(self.conn, self.owner), ())
        self.conn.rollback()
        self.refused(custody.inspect_public_roster, self.conn, self.owner)
        self.conn.execute("BEGIN")
        self.refused(custody.inspect_public_roster, self.conn, self.owner, absent=True)
        self.conn.close()
        self.refused(custody.inspect_public_roster, self.conn, self.owner)

    def test_complete_roster_is_sorted_fresh_query_only_and_never_decrypted(self):
        self.install()
        for version in reversed(range(1, 17)):
            self.insert(binding(self.owner, version=version, client=f"synthetic-client-{version}"))
        expected = tuple(custody.inspect_public_binding(self.conn, self.owner,
            binding(self.owner, version=version, client=f"synthetic-client-{version}")) for version in range(1, 17))
        before = tuple(self.conn.iterdump())
        self.conn.commit()
        self.conn.execute("PRAGMA query_only=ON")
        self.conn.execute("BEGIN")
        with patch.object(custody, "_key", side_effect=AssertionError("key touched")), \
                patch.object(custody, "open_x", side_effect=AssertionError("secret touched")), \
                patch.object(custody, "AESGCM", side_effect=AssertionError("cipher touched")), \
                patch("catchplate.operator_publication.assert_held", side_effect=AssertionError("writer touched")):
            actual = custody.inspect_public_roster(self.conn, self.owner)
        self.assertIs(type(actual), tuple)
        self.assertEqual(actual, expected)
        self.assertEqual([item["config_version"] for item in actual], list(range(1, 17)))
        self.assertNotIn(SECRET, json.dumps(actual))
        self.assertEqual(tuple(self.conn.iterdump()), before)
        actual[0]["public_profile"]["scopes"].clear()
        self.assertEqual(custody.inspect_public_roster(self.conn, self.owner), expected)

    def test_roster_refuses_wrong_owner_schema_and_any_invalid_retained_row(self):
        self.install()
        self.insert()
        self.refused(custody.inspect_public_roster, self.conn,
            owner("22345678-1234-4234-8234-123456789abc"))
        for sql, parameters in ((f"DROP TRIGGER {custody.TABLE}_retained", ()),
                (f"INSERT INTO {custody.TABLE} VALUES(?,?,?,?)", (2, "{}", b"n" * 12, b"x" * 32)),
                (f"INSERT INTO {custody.TABLE} VALUES(?,?,?,?)", (2, self.binding.profile_json, b"n" * 12, b"x" * 4113))):
            self.conn.execute("SAVEPOINT malformed")
            self.conn.execute(sql, parameters)
            self.refused(custody.inspect_public_roster, self.conn, self.owner)
            self.conn.execute("ROLLBACK TO malformed")
            self.conn.execute("RELEASE malformed")
        self.assertEqual(custody.inspect_public_roster(self.conn, self.owner), (self.inspect(),))


if __name__ == "__main__":
    unittest.main()
