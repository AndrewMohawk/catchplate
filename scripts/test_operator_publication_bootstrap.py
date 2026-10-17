#!/usr/bin/env python3
"""Synthetic config-independent publication-reader checks, not activation proof.

Real SQLite/WAL and flock in bounded temporary directories. No providers,
retained application state, secret creation, Docker or configured EX bootstrap.
"""
from __future__ import annotations

from dataclasses import replace
import fcntl
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import operator_publication as publication
from catchplate.operator_demo import MARKER, MARKER_BYTES


class BootstrapReaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="catchplate-publication-bootstrap-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.directory.chmod(0o700)
        self.marker = self.directory / MARKER
        self.marker.write_bytes(MARKER_BYTES)
        self.marker.chmod(0o600)
        self.lock = self.directory / publication.LOCK_NAME
        self.lock.touch(mode=0o600)
        self.database = self.directory / "catchplate.sqlite3"
        with sqlite3.connect(self.database) as conn:
            conn.execute("CREATE TABLE retained(value TEXT NOT NULL)")
            conn.execute("INSERT INTO retained VALUES('initial')")
        self.database.chmod(0o600)

    def admit(self, directory=None, **changes):
        flags = dict(operator_development=True, release_channel="dev", production_image=False,
            native_or_enrolled=False)
        return publication.admit_bootstrap_reader(directory or self.directory, **{**flags, **changes})

    def read(self, admission=None):
        with publication.bootstrap_read(admission or self.admit()) as conn:
            return tuple(row[0] for row in conn.execute("SELECT value FROM retained ORDER BY rowid"))

    def refused(self, operation):
        with self.assertRaises(publication.PublicationError) as caught:
            operation()
        self.assertEqual(str(caught.exception), "operator publication bootstrap refused")
        self.assertNotIn(str(self.directory), str(caught.exception))

    def files(self):
        return {path.name: (path.read_bytes(), path.stat().st_ino, path.stat().st_mode,
            path.stat().st_mtime_ns) for path in self.directory.iterdir() if path.is_file()}

    def test_read_snapshot_does_not_write_authority_or_create_key(self):
        before = self.files()
        with publication.bootstrap_read(self.admit()) as conn:
            self.assertTrue(conn.in_transaction)
            self.assertEqual(conn.execute("PRAGMA query_only").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT value FROM retained").fetchone()["value"], "initial")
            for sql in ("INSERT INTO retained VALUES('bad')", "CREATE TABLE unwanted(x)"):
                with self.assertRaises(sqlite3.OperationalError):
                    conn.execute(sql)
            with self.assertRaises(publication.PublicationError):
                publication.assert_held()
        self.assertEqual(self.files(), before)
        self.assertFalse((self.directory / "master.key").exists())
        self.assertIsNone(publication._pinned)

    def test_live_wal_commits_visible_and_transaction_is_a_snapshot(self):
        writer = sqlite3.connect(self.database)
        self.addCleanup(writer.close)
        self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("INSERT INTO retained VALUES('wal-before')")
        writer.commit()
        self.assertGreater((self.directory / "catchplate.sqlite3-wal").stat().st_size, 32)
        with publication.bootstrap_read(self.admit()) as reader:
            self.assertEqual(tuple(row[0] for row in reader.execute("SELECT value FROM retained")),
                ("initial", "wal-before"))
            writer.execute("INSERT INTO retained VALUES('wal-after')")
            writer.commit()
            self.assertEqual(tuple(row[0] for row in reader.execute("SELECT value FROM retained")),
                ("initial", "wal-before"))
        self.assertEqual(self.read(), ("initial", "wal-before", "wal-after"))

    def test_clean_checkpoint_wal_without_sidecars_can_restart(self):
        writer = sqlite3.connect(self.database)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("INSERT INTO retained VALUES('checkpointed')")
        writer.commit()
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        writer.close()
        self.assertEqual(self.database.read_bytes()[18:20], b"\x02\x02")
        self.assertFalse((self.directory / "catchplate.sqlite3-wal").exists())
        self.assertFalse((self.directory / "catchplate.sqlite3-shm").exists())
        before = self.database.read_bytes()
        self.assertEqual(self.read(), ("initial", "checkpointed"))
        self.assertEqual(self.database.read_bytes(), before)
        self.assertFalse((self.directory / "master.key").exists())

    def test_missing_existing_objects_never_created(self):
        for path in (self.lock, self.database, self.marker):
            with self.subTest(name=path.name):
                retained = self.directory / "retained-object"
                path.rename(retained)
                try:
                    self.refused(self.admit)
                    self.assertFalse(path.exists())
                    self.assertFalse((self.directory / "master.key").exists())
                finally:
                    retained.rename(path)

    def test_explicit_owner_and_process_identity_required(self):
        for changes in (dict(operator_development=False), dict(operator_development=1),
                dict(release_channel="production"), dict(production_image=True), dict(native_or_enrolled=True)):
            self.refused(lambda: self.admit(**changes))
        admission = self.admit()
        for index in range(3):
            process = list(admission.process)
            process[index] += 1
            self.refused(lambda: self.read(replace(admission, process=tuple(process))))
        with patch.object(publication, "_pinned", object()):
            self.refused(self.admit)
            self.refused(lambda: self.read(admission))
        with patch.object(publication.os, "geteuid", return_value=os.geteuid() + 1):
            self.refused(self.admit)

    def test_paths_symlinks_and_noncanonical_spellings_refused(self):
        alias = self.directory / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        for path in ("relative/path", "/", str(self.directory) + "/../" + self.directory.name,
                str(self.directory) + "/", alias, alias / "nested"):
            self.refused(lambda: self.admit(path))
        self.directory.chmod(0o750)
        self.refused(self.admit)

    def test_lock_database_marker_nonregular_or_changed_mode_refused(self):
        for path in (self.lock, self.database, self.marker):
            with self.subTest(name=path.name):
                retained = self.directory / "retained-object"
                path.rename(retained)
                try:
                    path.symlink_to(retained)
                    self.refused(self.admit)
                    path.unlink()
                    os.link(retained, path)
                    self.refused(self.admit)
                    path.unlink()
                    os.mkfifo(path, 0o600)
                    self.refused(self.admit)
                    path.unlink()
                finally:
                    retained.rename(path)
                path.chmod(0o640)
                self.refused(self.admit)
                path.chmod(0o600)
        self.marker.write_bytes(b"x" * len(MARKER_BYTES))
        self.refused(self.admit)

    def test_replaced_identity_not_adopted_after_admission(self):
        for path in (self.lock, self.database, self.marker):
            with self.subTest(name=path.name):
                admission = self.admit()
                retained = self.directory / "retained-object"
                path.rename(retained)
                path.write_bytes(retained.read_bytes())
                path.chmod(0o600)
                try:
                    self.refused(lambda: self.read(admission))
                finally:
                    path.unlink()
                    retained.rename(path)

    def test_context_rechecks_retained_identity_and_transaction(self):
        admission = self.admit()
        def change_marker():
            with publication.bootstrap_read(admission):
                self.marker.write_bytes(MARKER_BYTES)
        self.refused(change_marker)
        admission = self.admit()
        def end_transaction():
            with publication.bootstrap_read(admission) as conn:
                conn.rollback()
        self.refused(end_transaction)
        self.assertEqual(self.read(), ("initial",))

    def _substitute_after_first_read(self, kind):
        admission = self.admit()
        original_connect = sqlite3.connect
        marker = self.marker
        retained = self.directory / "retained-marker"
        sidecar = self.directory / "catchplate.sqlite3-shm"
        database = self.database
        fired = []
        entered = []

        class SubstitutingConnection(sqlite3.Connection):
            def execute(connection, sql, *args, **kwargs):
                result = super().execute(sql, *args, **kwargs)
                if sql == "SELECT name FROM sqlite_master LIMIT 1":
                    fired.append(True)
                    if kind == "marker":
                        marker.rename(retained)
                        marker.write_bytes(MARKER_BYTES)
                        marker.chmod(0o600)
                    else:
                        sidecar.symlink_to(database)
                return result

        def connect(*args, **kwargs):
            return original_connect(*args, **kwargs, factory=SubstitutingConnection)

        def read():
            with publication.bootstrap_read(admission):
                entered.append(True)

        try:
            with patch.object(publication.sqlite3, "connect", side_effect=connect):
                self.refused(read)
            self.assertEqual(fired, [True], "first-read substitution hook did not execute exactly once")
            self.assertEqual(entered, [], "reader yielded before rechecking the actual opened snapshot")
        finally:
            if retained.exists():
                marker.unlink()
                retained.rename(marker)
            if sidecar.is_symlink():
                sidecar.unlink()
        self.assertEqual(self.read(), ("initial",))

    def test_marker_substitution_after_first_sql_read_refuses_before_yield(self):
        self._substitute_after_first_read("marker")

    def test_unsafe_sidecar_after_first_sql_read_refuses_before_yield(self):
        self._substitute_after_first_read("sidecar")

    def test_directory_replacement_during_context_refused(self):
        admission = self.admit()
        retained = self.directory.with_name(self.directory.name + "-retained")
        def substitute():
            with publication.bootstrap_read(admission):
                self.directory.rename(retained)
                self.directory.mkdir(mode=0o700)
        try:
            self.refused(substitute)
        finally:
            self.directory.rmdir()
            retained.rename(self.directory)

    def test_bad_existing_sidecars_refused_before_sqlite_open(self):
        for suffix in ("-wal", "-shm", "-journal"):
            path = self.directory / ("catchplate.sqlite3" + suffix)
            for kind in ("symlink", "fifo", "mode", "hardlink"):
                with self.subTest(suffix=suffix, kind=kind):
                    if kind == "symlink":
                        path.symlink_to(self.database)
                    elif kind == "fifo":
                        os.mkfifo(path, 0o600)
                    elif kind == "hardlink":
                        os.link(self.marker, path)
                    else:
                        path.touch(mode=0o644)
                    try:
                        with patch.object(publication.sqlite3, "connect") as opened:
                            self.refused(self.read)
                        opened.assert_not_called()
                    finally:
                        path.unlink()

    def test_shared_existing_inode_blocks_exclusive_and_allows_shared(self):
        descriptor = os.open(self.lock, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            with publication.bootstrap_read(self.admit()):
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)

    def test_file_lock_wait_is_bounded_and_cleanup_releases_local_lock(self):
        admission = self.admit()
        descriptor = os.open(self.lock, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(publication, "ACQUISITION_SECONDS", 0.05):
                started = time.monotonic()
                self.refused(lambda: self.read(admission))
                self.assertLess(time.monotonic() - started, 0.5)
        finally:
            os.close(descriptor)
        self.assertEqual(self.read(), ("initial",))

    def test_local_lock_wait_and_nested_ownership_are_bounded(self):
        entered, release = threading.Event(), threading.Event()
        def hold():
            with publication.LOCAL_LOCK:
                entered.set()
                release.wait(2)
        holder = threading.Thread(target=hold)
        holder.start()
        try:
            self.assertTrue(entered.wait(1))
            with patch.object(publication, "ACQUISITION_SECONDS", 0.05):
                started = time.monotonic()
                self.refused(self.read)
                self.assertLess(time.monotonic() - started, 0.5)
        finally:
            release.set()
            holder.join(2)
        self.assertFalse(holder.is_alive())
        admission = self.admit()
        with publication.bootstrap_read(admission):
            self.refused(self.admit)
            self.refused(lambda: self.read(admission))
            self.refused(lambda: self._exclusive())

    @staticmethod
    def _exclusive():
        with publication.exclusive(startup=True):
            raise AssertionError("bootstrap reader acquired configured EX")

    def test_fresh_process_blocks_config_secret_and_database_imports(self):
        program = '''
import importlib.abc, sys
class Forbidden(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {"catchplate.config", "catchplate.db", "catchplate.crypto", "catchplate.operator_provider_custody"}:
            raise AssertionError("forbidden bootstrap import")
sys.meta_path.insert(0, Forbidden())
sys.path.insert(0, sys.argv[1])
from catchplate import operator_publication as p
a = p.admit_bootstrap_reader(sys.argv[2], operator_development=True,
    release_channel="dev", production_image=False, native_or_enrolled=False)
with p.bootstrap_read(a) as conn:
    assert conn.execute("SELECT value FROM retained").fetchone()[0] == "initial"
assert p._pinned is None
assert not {"catchplate.config", "catchplate.db", "catchplate.crypto", "catchplate.operator_provider_custody"}.intersection(sys.modules)
'''
        before = self.files()
        result = subprocess.run([sys.executable, "-B", "-c", program, str(ROOT), str(self.directory)],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(self.files(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
