#!/usr/bin/env python3
"""Synthetic unit checks for unwired operator-provider custody primitives only.

No providers, Docker, retained application state or config imports. Writer tests
mock only the publication-ownership assertion; these are not startup, audit,
publication-lock, API, activation or operator-configuration acceptance tests.
"""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import operator_provider_custody as custody

CLIENT = "123-synthetic.apps.googleusercontent.com"
CALLBACK = "https://console.example.com/api/oauth/callback/google"
SECRET = "synthetic-provider-secret-not-real"
KEY = bytes(range(32))


def owner(identifier=None):
    return custody.admit_development_owner(identifier or str(uuid.uuid4()),
        operator_development=True, release_channel="dev", production_image=False, native_or_enrolled=False)


def binding(admission, version=1, client=CLIENT, callback=CALLBACK):
    return custody.bind_google(admission, config_version=version,
        public_profile=custody.google._record(client, callback))


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.owner = owner()
        self.binding = binding(self.owner)
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("BEGIN IMMEDIATE")
        self.addCleanup(self.conn.close)

    def install(self):
        with patch("serverware.operator_publication.assert_held") as held:
            custody.install_empty_store(self.conn, self.owner)
        self.assertEqual(held.call_count, 1)

    def insert(self, selected=None, secret=SECRET):
        with patch("serverware.operator_publication.assert_held") as held:
            custody.insert_secret(self.conn, self.owner, selected or self.binding, key=KEY, secret=secret)
        self.assertEqual(held.call_count, 1)

    def refused(self, function, *args, absent=False, **kwargs):
        error = custody.CustodyAbsent if absent else custody.CustodyError
        with self.assertRaises(error) as caught:
            function(*args, **kwargs)
        expected = "operator provider custody absent" if absent else "operator provider custody refused"
        self.assertEqual(str(caught.exception), expected)
        self.assertNotIn(SECRET, repr(caught.exception))

    def test_aead_roundtrip_and_public_projection(self):
        sealed = custody.seal(self.owner, self.binding, key=KEY, secret=SECRET)
        material = custody.open_secret(self.owner, sealed, key=KEY)
        self.assertEqual(material.secret, SECRET)
        self.assertNotIn(SECRET, repr(material))
        self.assertNotIn(repr(sealed.ciphertext), repr(sealed))
        public = material.public_view()
        self.assertEqual(set(public), {"schema", "owner_id", "config_version", "public_profile", "secret_present"})
        self.assertTrue(public["secret_present"])
        self.assertNotIn(SECRET, json.dumps(public))
        self.assertEqual(public["public_profile"], custody.google._record(CLIENT, CALLBACK))
        second = custody.seal(self.owner, self.binding, key=KEY, secret=SECRET)
        self.assertNotEqual(sealed.nonce, second.nonce)

    def test_owner_version_and_exact_profile_are_aad_bound(self):
        sealed = custody.seal(self.owner, self.binding, key=KEY, secret=SECRET)
        other = owner()
        changes = [(other, binding(other)), (self.owner, binding(self.owner, 2)),
            (self.owner, binding(self.owner, client="999-other.apps.googleusercontent.com")),
            (self.owner, binding(self.owner, callback="https://another.example.com/api/oauth/callback/google"))]
        for admitted, changed in changes:
            with self.subTest(binding=changed):
                self.refused(custody.open_secret, admitted, replace(sealed, binding=changed), key=KEY)
        self.refused(custody.open_secret, self.owner, sealed, key=b"x" * 32)
        self.refused(custody.open_secret, self.owner,
            replace(sealed, ciphertext=sealed.ciphertext[:-1] + bytes([sealed.ciphertext[-1] ^ 1])), key=KEY)

    def test_explicit_development_owner_and_process_identity(self):
        good = dict(operator_development=True, release_channel="dev", production_image=False, native_or_enrolled=False)
        for key, bad in (("operator_development", False), ("operator_development", 1),
                ("release_channel", "production"), ("production_image", True), ("native_or_enrolled", True)):
            self.refused(custody.admit_development_owner, self.owner.owner_id, **{**good, key: bad})
        self.refused(custody.admit_development_owner, "not-a-uuid", **good)
        for changed in (replace(self.owner, uid=self.owner.uid + 1), replace(self.owner, pid=self.owner.pid + 1)):
            self.refused(custody.bind_google, changed, config_version=1,
                public_profile=custody.google._record(CLIENT, CALLBACK))

    def test_closed_profile_and_scalar_bounds(self):
        profile = custody.google._record(CLIENT, CALLBACK)
        for changed in ({**profile, "client_secret": SECRET}, {**profile, "scopes": ["openid"]},
                {**profile, "token_url": "https://other.example.com/token"},
                {**profile, "redirect_uri": "http://console.example.com/api/oauth/callback/google"}):
            self.refused(custody.bind_google, self.owner, config_version=1, public_profile=changed)
        for version in (True, 0, 17, 1.0, "1"):
            self.refused(custody.bind_google, self.owner, config_version=version, public_profile=profile)
        for secret in ("", " leading", "trailing ", "line\nvalue", "nul\0value", "x" * 4097, "\ud800", 42):
            self.refused(custody.seal, self.owner, self.binding, key=KEY, secret=secret)
        for key in (b"short", bytearray(KEY), "x" * 32):
            self.refused(custody.seal, self.owner, self.binding, key=key, secret=SECRET)
        boundary = "é" * 2048
        sealed = custody.seal(self.owner, self.binding, key=KEY, secret=boundary)
        self.assertEqual(custody.open_secret(self.owner, sealed, key=KEY).secret, boundary)
        self.refused(custody.open_secret, self.owner,
            replace(sealed, binding=replace(self.binding, profile_json="\ud800")), key=KEY)

    def test_transaction_and_real_publication_assertion_required(self):
        self.refused(custody.install_empty_store, self.conn, self.owner)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[0], 0)
        self.conn.rollback()
        with patch("serverware.operator_publication.assert_held") as held:
            self.refused(custody.install_empty_store, self.conn, self.owner)
        held.assert_not_called()
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY)

    def test_closed_connection_errors_are_fixed(self):
        self.conn.close()
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY)
        with patch("serverware.operator_publication.assert_held") as held:
            self.refused(custody.install_empty_store, self.conn, self.owner)
            self.refused(custody.insert_secret, self.conn, self.owner, self.binding, key=KEY, secret=SECRET)
        held.assert_not_called()

    def test_atomic_rollback_and_ciphertext_storage(self):
        self.install()
        self.insert()
        self.assertTrue(self.conn.in_transaction)
        actual = custody.read_secret(self.conn, self.owner, self.binding, key=KEY)
        self.assertEqual(actual.secret, SECRET)
        self.assertNotIn(SECRET, "\n".join(self.conn.iterdump()))
        self.conn.rollback()
        self.conn.execute("BEGIN")
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY, absent=True)

    def test_absent_malformed_and_missing_record_are_distinct(self):
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY, absent=True)
        self.install()
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY)
        self.conn.execute(f"DROP TRIGGER {custody.TABLE}_retained")
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY)
        with patch("serverware.operator_publication.assert_held"):
            self.refused(custody.install_empty_store, self.conn, self.owner)

    def test_case_variant_schema_is_malformed_not_absent(self):
        self.conn.execute("CREATE TABLE Operator_Provider_Custody (unexpected TEXT)")
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY)
        before = tuple(self.conn.iterdump())
        with patch("serverware.operator_publication.assert_held"):
            self.refused(custody.install_empty_store, self.conn, self.owner)
        self.assertEqual(tuple(self.conn.iterdump()), before)

    def test_exact_version_no_latest_fallback_and_owner_mismatch(self):
        self.install()
        self.insert(binding(self.owner, 2))
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY)
        other = owner()
        self.refused(custody.read_secret, self.conn, other, binding(other, 2), key=KEY)
        self.assertEqual(custody.read_secret(self.conn, self.owner, binding(self.owner, 2), key=KEY).secret, SECRET)

    def test_retention_guards_and_duplicate_insert(self):
        self.install()
        self.insert()
        with patch("serverware.operator_publication.assert_held"):
            self.refused(custody.insert_secret, self.conn, self.owner, self.binding, key=KEY, secret="replacement")
        for command in (f"DELETE FROM {custody.TABLE}", f"UPDATE {custody.TABLE} SET config_version=2",
                f"INSERT OR REPLACE INTO {custody.TABLE} SELECT * FROM {custody.TABLE}",
                f"DELETE FROM {custody.META}", f"UPDATE {custody.META} SET owner_id='other'",
                f"INSERT OR REPLACE INTO {custody.META} SELECT * FROM {custody.META}"):
            with self.subTest(command=command), self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute(command)
        self.assertEqual(custody.read_secret(self.conn, self.owner, self.binding, key=KEY).secret, SECRET)

    def test_structural_corruption_and_extra_schema_refused(self):
        self.install()
        self.conn.execute(f"INSERT INTO {custody.TABLE} VALUES(?,?,?,?)", (1, self.binding.profile_json, b"n" * 12, b"x" * 5000))
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY)
        self.conn.rollback()
        self.conn.execute("BEGIN")
        self.install()
        self.insert()
        self.conn.execute(f"CREATE INDEX {custody.TABLE}_unexpected ON {custody.TABLE}(profile_json)")
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY)

    def test_bounded_version_storage_and_read_only_snapshot(self):
        self.install()
        for version in range(1, custody.MAX_VERSIONS + 1):
            self.insert(binding(self.owner, version))
        before = tuple(self.conn.iterdump())
        self.conn.commit()
        self.conn.execute("PRAGMA query_only=ON")
        self.conn.execute("BEGIN")
        self.assertEqual(custody.read_secret(self.conn, self.owner, self.binding, key=KEY).secret, SECRET)
        self.assertEqual(tuple(self.conn.iterdump()), before)
        with patch("serverware.operator_publication.assert_held"):
            self.refused(custody.insert_secret, self.conn, self.owner, self.binding, key=KEY, secret=SECRET)

    def test_blob_type_and_oversized_profile_refused_before_fetch(self):
        self.install()
        for version, profile, nonce, ciphertext in (
                (1, self.binding.profile_json, "n" * 12, b"x" * 32),
                (2, " " * (custody.MAX_PROFILE_BYTES + 1), b"n" * 12, b"x" * 32)):
            self.conn.execute(f"INSERT INTO {custody.TABLE} VALUES(?,?,?,?)", (version, profile, nonce, ciphertext))
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY)

    def test_oversized_and_malformed_schema_markers_refused(self):
        self.install()
        self.insert()
        trigger = next(sql for name, _, _, sql in custody._DEFINITIONS if name == custody.META + "_immutable")
        for schema, owner_id in ((custody.SCHEMA + "x" * 10000, self.owner.owner_id),
                (custody.SCHEMA, self.owner.owner_id + "x" * 10000),
                (custody.SCHEMA.encode("utf-8"), self.owner.owner_id)):
            self.conn.execute(f"DROP TRIGGER {custody.META}_immutable")
            self.conn.execute(f"UPDATE {custody.META} SET schema=?,owner_id=?", (schema, owner_id))
            self.conn.execute(trigger)
            self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY)

    def test_noncanonical_profile_duplicate_keys_refused(self):
        self.install()
        duplicate = self.binding.profile_json[:-1] + ',"client_id":"' + CLIENT + '"}'
        self.conn.execute(f"INSERT INTO {custody.TABLE} VALUES(?,?,?,?)", (1, duplicate, b"n" * 12, b"x" * 32))
        self.refused(custody.read_secret, self.conn, self.owner, self.binding, key=KEY)


class ExistingKeyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="serverware-custody-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.directory.chmod(0o700)
        self.owner = owner()
        self.marker = self.directory / custody.MARKER
        self.marker.write_bytes(custody.MARKER_BYTES)
        self.marker.chmod(0o600)
        self.key = self.directory / "master.key"
        self.key.write_bytes(KEY)
        self.key.chmod(0o600)

    def refused(self, directory=None):
        with self.assertRaises(custody.CustodyError) as caught:
            custody.read_existing_master_key(directory or self.directory, self.owner)
        self.assertEqual(str(caught.exception), "operator provider custody refused")
        self.assertNotIn(str(self.directory), str(caught.exception))

    def test_existing_key_only_and_no_file_changes(self):
        before = {item.name: (item.read_bytes(), item.stat().st_mode, item.stat().st_mtime_ns)
            for item in self.directory.iterdir()}
        self.assertEqual(custody.read_existing_master_key(self.directory, self.owner), KEY)
        after = {item.name: (item.read_bytes(), item.stat().st_mode, item.stat().st_mtime_ns)
            for item in self.directory.iterdir()}
        self.assertEqual(before, after)
        self.key.chmod(0o400)
        self.assertEqual(custody.read_existing_master_key(self.directory, self.owner), KEY)
        self.key.unlink()
        self.refused()
        self.assertFalse(self.key.exists())

    def test_key_size_mode_hardlink_and_symlink_refusal(self):
        for value in (b"x" * 31, b"x" * 33, b""):
            self.key.write_bytes(value)
            self.refused()
        self.key.write_bytes(KEY)
        self.key.chmod(0o640)
        self.refused()
        self.key.chmod(0o600)
        extra = self.directory / "linked.key"
        os.link(self.key, extra)
        self.refused()
        extra.unlink()
        self.key.rename(extra)
        self.key.symlink_to(extra)
        self.refused()

    def test_marker_directory_and_ancestor_symlinks_refused(self):
        self.marker.write_bytes(custody.MARKER_BYTES.replace(b"false", b"true "))
        self.refused()
        self.marker.write_bytes(custody.MARKER_BYTES)
        self.directory.chmod(0o750)
        self.refused()
        self.directory.chmod(0o700)
        alias = self.directory / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        self.refused(alias)
        self.refused(str(alias) + "/nested")
        self.refused(str(self.directory) + "/../" + self.directory.name)
        self.refused("relative/path")

    def test_marker_missing_symlink_and_changed_owner_refused(self):
        self.marker.unlink()
        self.refused()
        self.assertFalse(self.marker.exists())
        target = self.directory / "other-marker"
        target.write_bytes(custody.MARKER_BYTES)
        target.chmod(0o600)
        self.marker.symlink_to(target)
        self.refused()
        self.marker.unlink()
        self.marker.write_bytes(custody.MARKER_BYTES)
        self.marker.chmod(0o600)
        self.owner = replace(self.owner, uid=self.owner.uid + 1)
        self.refused()

    def test_nonregular_objects_and_identity_change_refused(self):
        self.key.unlink()
        os.mkfifo(self.key, 0o600)
        self.refused()
        self.key.unlink()
        self.key.write_bytes(KEY)
        self.key.chmod(0o600)
        original = custody._read_file

        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[1] == "master.key":
                self.key.unlink()
                self.key.write_bytes(KEY)
                self.key.chmod(0o600)
            return result

        with patch.object(custody, "_read_file", side_effect=changed):
            self.refused()

    def test_import_independent_file_and_sqlite_read(self):
        dbpath = self.directory / "synthetic.sqlite3"
        conn = sqlite3.connect(dbpath)
        try:
            conn.execute("BEGIN IMMEDIATE")
            with patch("serverware.operator_publication.assert_held"):
                custody.install_empty_store(conn, self.owner)
                custody.insert_secret(conn, self.owner, binding(self.owner), key=KEY, secret=SECRET)
            conn.commit()
        finally:
            conn.close()
        before = {item.name: (item.read_bytes(), item.stat().st_mtime_ns) for item in self.directory.iterdir()}
        program = '''
import importlib.abc, pathlib, sqlite3, sys
class Forbidden(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {"serverware.config", "serverware.crypto", "serverware.db"}:
            raise AssertionError("forbidden import")
sys.meta_path.insert(0, Forbidden())
sys.path.insert(0, sys.argv[1])
from serverware import operator_provider_custody as c
o = c.admit_development_owner(sys.argv[3], operator_development=True,
    release_channel="dev", production_image=False, native_or_enrolled=False)
b = c.bind_google(o, config_version=1, public_profile=c.google._record(
    "123-synthetic.apps.googleusercontent.com", "https://console.example.com/api/oauth/callback/google"))
d = pathlib.Path(sys.argv[2])
k = c.read_existing_master_key(d, o)
conn = sqlite3.connect((d / "synthetic.sqlite3").as_uri() + "?mode=ro", uri=True)
conn.execute("PRAGMA query_only=ON")
conn.execute("BEGIN")
assert c.read_secret(conn, o, b, key=k).secret == "synthetic-provider-secret-not-real"
assert not {"serverware.config", "serverware.crypto", "serverware.db"}.intersection(sys.modules)
conn.close()
'''
        result = subprocess.run([sys.executable, "-B", "-c", program, str(ROOT), str(self.directory), self.owner.owner_id],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(result.stdout, b"")
        after = {item.name: (item.read_bytes(), item.stat().st_mtime_ns) for item in self.directory.iterdir()}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main(verbosity=2)
