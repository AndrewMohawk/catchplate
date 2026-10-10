#!/usr/bin/env python3
"""Synthetic tempfile provider-key tests; no configured owner, network or live data.

Successful initializer tests stub only publication.assert_held. The setup owner
must separately prove managed history absence and real EX/SQLite integration.
"""
from __future__ import annotations

import base64
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
from serverware import operator_provider_key as keys


class ProviderKeyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="provider-key-pure-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory, self.data = self.root / "provider", self.root / "data"
        self.directory.mkdir(mode=0o700)
        self.data.mkdir(mode=0o700)
        self.path = self.directory / keys.FILENAME
        self.admission = keys.admit_directory(self.directory, data_directory=self.data)
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.execute("BEGIN IMMEDIATE")

    def keep(self, value):
        self.addCleanup(keys.close_pin, value)
        return value

    def initialize(self, admission=None):
        with patch("serverware.operator_publication.assert_held") as held:
            result = keys.initialize_first(admission or self.admission, self.conn,
                no_retained_provider_state=True)
        held.assert_called_once_with()
        return self.keep(result)

    def refused(self, function, *args, **kwargs):
        with self.assertRaises(keys.ProviderKeyError) as caught:
            function(*args, **kwargs)
        self.assertEqual(str(caught.exception), "operator provider key unavailable")
        self.assertNotIn(str(self.root), repr(caught.exception))

    def write_record(self, raw):
        self.path.write_bytes(raw)
        self.path.chmod(0o600)

    def file_state(self):
        info = self.path.stat()
        # Ordinary reads may update atime; authority bytes/identity must not.
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns), self.path.read_bytes()

    def test_first_prepare_creates_closed_private_record_not_master_key(self):
        value = self.initialize()
        keys.check_pin(value)
        record = json.loads(self.path.read_bytes())
        self.assertEqual(set(record), {"schema", "owner_id", "key"})
        self.assertEqual(record["schema"], keys.SCHEMA)
        self.assertEqual(str(uuid.UUID(value.owner_id)), value.owner_id)
        self.assertTrue(base64.b64decode(record["key"]) == value.material)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.data.iterdir()), [])
        self.assertNotIn("material", repr(value))
        self.assertNotIn(record["key"], repr(value))

    def test_existing_read_never_creates_and_exact_owner_is_required(self):
        self.refused(keys.read_existing_pinned, self.admission, str(uuid.uuid4()))
        self.assertEqual(list(self.directory.iterdir()), [])
        value = self.initialize()
        before = self.file_state()
        read = self.keep(keys.read_existing_pinned(self.admission, value.owner_id))
        self.assertTrue(read.material == value.material)
        self.assertEqual(read.owner_id, value.owner_id)
        self.assertTrue(self.file_state() == before)
        for owner in (str(uuid.uuid4()), value.owner_id.upper(), "invalid", None, 1):
            with self.subTest(owner_type=type(owner).__name__):
                self.refused(keys.read_existing_pinned, self.admission, owner)

    def test_real_publication_assertion_and_explicit_proof_are_required(self):
        self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=True)
        with patch("serverware.operator_publication.assert_held") as held:
            for proof in (False, None, 1, "true"):
                self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=proof)
            held.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_live_writable_transaction_is_required(self):
        with patch("serverware.operator_publication.assert_held"):
            self.conn.rollback()
            self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=True)
            self.conn.execute("PRAGMA query_only=ON")
            self.conn.execute("BEGIN")
            self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=True)
            self.conn.rollback()
            self.conn.execute("PRAGMA query_only=OFF")
            self.conn.execute("PRAGMA read_uncommitted=ON")
            self.conn.execute("BEGIN IMMEDIATE")
            self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=True)
            self.conn.close()
            self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=True)
        self.assertFalse(self.path.exists())

    def test_provider_namespace_even_malformed_or_case_variant_refuses(self):
        with patch("serverware.operator_publication.assert_held"):
            for name in ("operator_provider_custody", "Operator_Provider_Custody_orphan"):
                self.conn.execute('CREATE TABLE "' + name + '" (x)')
                self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=True)
                self.conn.execute('DROP TABLE "' + name + '"')
        self.assertFalse(self.path.exists())

    def test_valid_orphan_recovery_preserves_owner_inode_and_bytes_after_rollback(self):
        first = self.initialize()
        before = self.file_state()
        self.conn.rollback()
        self.conn.execute("BEGIN IMMEDIATE")
        second = self.initialize()
        self.assertEqual(second.owner_id, first.owner_id)
        self.assertTrue(second.material == first.material)
        self.assertTrue(self.file_state() == before)
        with patch("serverware.operator_publication.assert_held"):
            self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=False)

    def test_missing_key_with_retained_namespace_never_recreates(self):
        value = self.initialize()
        keys.close_pin(value)
        self.path.unlink()
        self.conn.execute("CREATE TABLE operator_provider_custody_meta (owner)")
        with patch("serverware.operator_publication.assert_held"):
            self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=True)
        self.refused(keys.read_existing_pinned, self.admission, value.owner_id)
        self.assertFalse(self.path.exists())

    def test_durable_create_and_orphan_retry_both_fsync_file_and_directory(self):
        actual = os.fsync
        with patch.object(keys.os, "fsync", wraps=actual) as synced:
            self.initialize()
            self.assertGreaterEqual(synced.call_count, 2)
        with patch.object(keys.os, "fsync", wraps=actual) as synced:
            self.initialize()
            self.assertEqual(synced.call_count, 2)

    def test_failed_fsync_leaves_valid_orphan_for_explicit_retry_only(self):
        with patch("serverware.operator_publication.assert_held"), patch.object(keys.os, "fsync", side_effect=OSError("synthetic")):
            self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=True)
        raw, inode = self.path.read_bytes(), self.path.stat().st_ino
        value = self.initialize()
        self.assertTrue(self.path.read_bytes() == raw)
        self.assertEqual(self.path.stat().st_ino, inode)
        keys.check_pin(value)

    def test_partial_write_is_never_repaired_or_overwritten(self):
        with patch("serverware.operator_publication.assert_held"), patch.object(keys.os, "write", return_value=0):
            self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=True)
        before = self.file_state()
        with patch("serverware.operator_publication.assert_held"):
            self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=True)
        self.assertTrue(self.file_state() == before)

    def test_malformed_record_grammar_never_repaired(self):
        valid = {"schema": keys.SCHEMA, "owner_id": str(uuid.uuid4()), "key": base64.b64encode(bytes(range(32))).decode()}
        records = [b"", b"partial", b"x" * 513, b"[]", b"{\"schema\":", keys._canonical(valid) + b" ",
            keys._canonical({**valid, "extra": True}), keys._canonical({**valid, "schema": "other"}),
            keys._canonical({**valid, "owner_id": valid["owner_id"].upper()}),
            keys._canonical({**valid, "key": "!" * 44}), keys._canonical({**valid, "key": base64.b64encode(b"short").decode()}),
            b'{"owner_id":"duplicate",' + keys._canonical(valid)[1:]]
        for raw in records:
            with self.subTest(record_size=len(raw)):
                self.write_record(raw)
                self.refused(keys.read_existing_pinned, self.admission, valid["owner_id"])
                with patch("serverware.operator_publication.assert_held"):
                    self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=True)
                self.assertTrue(self.path.read_bytes() == raw)

    def test_private_modes_file_owner_and_special_files_refuse(self):
        value = self.initialize()
        wrong_owner = list(self.path.stat())
        wrong_owner[4] = os.geteuid() + 1
        self.refused(keys._file_identity, os.stat_result(wrong_owner))
        for mode in (0o400, 0o640, 0o644):
            self.path.chmod(mode)
            self.refused(keys.read_existing_pinned, self.admission, value.owner_id)
        self.path.chmod(0o600)
        self.directory.chmod(0o750)
        self.refused(keys.read_existing_pinned, self.admission, value.owner_id)
        self.directory.chmod(0o700)
        keys.close_pin(value)
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        self.refused(keys.read_existing_pinned, self.admission, value.owner_id)
        self.path.unlink()
        self.path.mkdir(mode=0o700)
        self.refused(keys.read_existing_pinned, self.admission, value.owner_id)

    def test_symlink_hardlink_and_extra_namespace_refuse(self):
        value = self.initialize()
        held = self.root / "held"
        self.path.rename(held)
        self.path.symlink_to(held)
        self.refused(keys.read_existing_pinned, self.admission, value.owner_id)
        self.path.unlink()
        os.link(held, self.path)
        self.refused(keys.read_existing_pinned, self.admission, value.owner_id)
        self.path.unlink()
        held.rename(self.path)
        (self.directory / "notification-key.json").touch(mode=0o600)
        self.refused(keys.read_existing_pinned, self.admission, value.owner_id)
        self.refused(keys.admit_directory, self.directory, data_directory=self.data)

    def test_directory_paths_must_exist_be_canonical_separate_and_not_symlinked(self):
        nested = self.data / "private"
        nested.mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for path, data in ((self.data, self.data), (nested, self.data), (self.root, self.data),
                ("relative", self.data), (str(self.directory) + "/", self.data),
                (str(self.root) + "/./provider", self.data), (alias / "provider", self.data),
                (self.directory, alias / "data"), (self.root / "missing", self.data)):
            self.refused(keys.admit_directory, path, data_directory=data)

    def test_process_environment_and_owner_pins_refuse_drift(self):
        value = self.initialize()
        with patch.dict(os.environ, {"SERVERWARE_PROVIDER_SYNTHETIC_TEST": "changed"}):
            self.refused(keys.check_pin, value)
            self.refused(keys.read_existing_pinned, self.admission, value.owner_id)
        with patch.dict(os.environ, {"SERVERWARE_CONTROL_PLANE_STARTUP_VALIDATED_PID": str(os.getpid())}):
            keys.check_pin(value)
        for admission in (replace(value, owner_id=str(uuid.uuid4())),
                replace(value, directory=replace(self.admission, process=(os.getpid() + 1, os.geteuid(), os.getegid()))),
                replace(value, material=b"z" * 32)):
            self.refused(keys.check_pin, admission)

    def test_replaced_or_rewritten_key_is_not_adopted(self):
        value = self.initialize()
        raw = self.path.read_bytes()
        self.path.rename(self.root / "old")
        self.write_record(raw)
        self.refused(keys.check_pin, value)
        replacement = self.keep(keys.read_existing_pinned(self.admission, value.owner_id))
        self.write_record(raw)
        info = self.path.stat()
        os.utime(self.path, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000))
        self.refused(keys.check_pin, replacement)

    def test_replaced_provider_or_data_directory_is_not_adopted(self):
        value = self.initialize()
        self.data.rename(self.root / "old-data")
        self.data.mkdir(mode=0o700)
        self.refused(keys.check_pin, value)
        self.data.rmdir()
        (self.root / "old-data").rename(self.data)
        self.directory.rename(self.root / "old-provider")
        self.directory.mkdir(mode=0o700)
        self.refused(keys.check_pin, value)

    def test_raced_replacement_before_pin_return_refuses(self):
        value = self.initialize()
        original = keys._read
        replaced = []

        def race(descriptor):
            result = original(descriptor)
            if not replaced:
                replaced.append(True)
                raw = self.path.read_bytes()
                self.path.rename(self.root / "raced")
                self.write_record(raw)
            return result

        with patch.object(keys, "_read", side_effect=race):
            self.refused(keys.read_existing_pinned, self.admission, value.owner_id)

    def test_exclusive_creation_never_overwrites_raced_file(self):
        original = os.open
        raw = b"synthetic-raced-owner"

        def race(path, flags, *args, **kwargs):
            if path == keys.FILENAME and flags & os.O_CREAT:
                self.write_record(raw)
            return original(path, flags, *args, **kwargs)

        with patch("serverware.operator_publication.assert_held"), patch.object(keys.os, "open", side_effect=race):
            self.refused(keys.initialize_first, self.admission, self.conn, no_retained_provider_state=True)
        self.assertTrue(self.path.read_bytes() == raw)

    def test_closed_pin_is_not_reusable_and_cleanup_is_idempotent(self):
        value = self.initialize()
        keys.close_pin(value)
        keys.close_pin(value)
        self.refused(keys.check_pin, value)

    def test_import_independent_existing_read_and_pin_checks(self):
        value = self.initialize()
        program = '''
import importlib.abc, pathlib, sys
class Forbidden(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {"serverware.config", "serverware.db", "serverware.crypto"}:
            raise AssertionError("configured import")
sys.meta_path.insert(0, Forbidden())
sys.path.insert(0, sys.argv[1])
from serverware import operator_provider_key as k
d = k.admit_directory(sys.argv[2], data_directory=sys.argv[3])
p = k.read_existing_pinned(d, sys.argv[4])
k.check_pin(p)
k.close_pin(p)
assert not {"serverware.config", "serverware.db", "serverware.crypto"}.intersection(sys.modules)
'''
        child = subprocess.run([sys.executable, "-B", "-c", program, str(ROOT),
            str(self.directory), str(self.data), value.owner_id], capture_output=True, timeout=15)
        self.assertEqual(child.returncode, 0, "cold subprocess refused")
        self.assertEqual(child.stdout, b"")


if __name__ == "__main__":
    unittest.main()
