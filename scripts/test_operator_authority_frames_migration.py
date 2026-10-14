#!/usr/bin/env python3
"""One focused real .350 -> .351 migration/preservation/cold-start test.

Reuse the existing genuine ordinary-store fixture, never its historical pins
or test suite. Only disposable synthetic state; no live/provider admission.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import unittest

sys.path.insert(0, "/app/scripts")
import test_operator_authority_source_revision_migration as fixture
import migrate_operator_authority_frames as frames

fixture.migration = migration = frames.engine
fixture.OLD_COMMIT = migration.OLD_COMMIT
fixture.TARGET_COMMIT = migration.TARGET_COMMIT


class FramesMigrationTest(fixture.AuthoritySourceRevisionMigrationTests):
    @classmethod
    def child(cls, operation, directory, *, expected):
        result = subprocess.run([sys.executable, "-B", __file__, operation, str(directory)],
            env={**fixture.ordinary.child_environment(), "PYTHONPATH": "/app/scripts"},
            capture_output=True, timeout=55)
        if result.returncode != 0:
            # The fixture has synthetic material, but only its code traceback
            # (not captured stdout containing generated values) is diagnostic.
            raise AssertionError("migration child failed: " + result.stderr.decode(errors="replace")[-6000:])
        fixture.require(result.stdout == expected)

    def test_frames_transition(self):
        before, files = self.logical(), self.files()
        reviewed = self.plan()
        self.assertEqual(self.files(), files)
        self.assertEqual((len(reviewed["rows"]), len(self.pinned["target"]["optionalTables"])), (218, 219))
        altered = deepcopy(self.pinned)
        altered["target"]["sourceContractDigest"] = "sha256:" + "0" * 64
        self.assert_refused_without_write(lambda: migration.plan(self.directory, altered, self.helpers))
        # The new DDL and all old guards must roll back together before COMMIT.
        def fail(stage):
            if stage == "after_additions":
                raise RuntimeError("synthetic precommit interruption")
        with self.assertRaisesRegex(RuntimeError, "synthetic precommit"):
            self.apply(reviewed, checkpoint=fail)
        self.assertEqual(self.files(), files)
        self.assertEqual(self.logical(), before)
        reviewed = self.plan()  # Rollback may change inode timestamps, not bytes.
        receipt = self.apply(reviewed)
        self.assertEqual(receipt["status"], "committed")
        after = self.logical()
        migration.require_delta(before["schema"], after["schema"], self.pinned)
        self.assertEqual(set(after["rows"]) - set(before["rows"]), {frames.FRAME})
        self.assertEqual(after["rows"][frames.FRAME]["values"], [])
        expected = deepcopy(before)
        expected["schema"] = after["schema"]
        expected["rows"][frames.FRAME] = after["rows"][frames.FRAME]
        expected["rows"][migration.CONTRACT_TABLE] = after["rows"][migration.CONTRACT_TABLE]
        self.assertEqual(after, expected)
        self.assertEqual(receipt["orderedAudit"], reviewed["orderedAudit"])
        self.assertEqual({k: v for k, v in self.files().items() if k != migration.DATABASE},
            {k: v for k, v in files.items() if k != migration.DATABASE})
        self.assertEqual(migration.sha(self.backup.read_bytes()), files[migration.DATABASE][2])
        self.assert_refused_without_write(self.plan)
        self.assert_refused_without_write(lambda: self.apply(reviewed))
        with self.db() as conn:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "frame admission is disabled"):
                conn.execute('INSERT INTO "' + frames.FRAME + '" VALUES(?,?,?,?,?,?,?)',
                    ("sha256:" + "1" * 64, "sha256:" + "2" * 64, 0, 1,
                     "sha256:" + "3" * 64, b"x", "sha256:" + "4" * 64))
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE policy_authority_schema_contracts SET installed_at='changed'")
        started = datetime.now(timezone.utc)
        self.child("--cold-start", self.directory, expected=fixture.START_OUTPUT)
        finished, started_state = datetime.now(timezone.utc), self.logical()
        rows = started_state["rows"]["serverware_store_migrations"]
        name_index, time_index = rows["columns"].index("migration"), rows["columns"].index("applied_at")
        selected = [row for row in rows["values"] if row[name_index] == ["str", "policy_candidate_authority"]]
        prior = [row for row in after["rows"]["serverware_store_migrations"]["values"]
            if row[name_index] == ["str", "policy_candidate_authority"]]
        self.assertEqual((len(selected), len(prior)), (1, 1))
        observed = datetime.fromisoformat(selected[0][time_index][1])
        self.assertGreaterEqual(observed, started)
        self.assertLessEqual(observed, finished)
        selected[0][time_index] = prior[0][time_index]
        rows["values"].sort(key=migration.canonical)
        self.assertEqual(started_state, after)
        self.assertEqual({k: v for k, v in self.files().items() if k != migration.DATABASE},
            {k: v for k, v in files.items() if k != migration.DATABASE})
        self.assertEqual((list(self.custody.iterdir()), list(self.provider.iterdir())), ([], []))


if __name__ == "__main__":
    os.umask(0o077)
    signal.alarm(120)
    sys.addaudithook(fixture.local_only)
    if len(sys.argv) == 3 and sys.argv[1] in {"--seed", "--cold-start"}:
        fixture._OWNED_ROOT = Path(sys.argv[2])
        fixture.require(fixture._OWNED_ROOT.is_absolute() and fixture._OWNED_ROOT.is_relative_to("/tmp")
            and fixture._OWNED_ROOT != Path("/tmp"))
        {"--seed": fixture.seed, "--cold-start": fixture.cold_start}[sys.argv[1]](sys.argv[2])
    elif len(sys.argv) == 1:
        suite = unittest.TestSuite([FramesMigrationTest("test_frames_transition")])
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        ok = result.wasSuccessful() and result.testsRun == 1 and not result.skipped
        print(json.dumps({"schema": "serverware.operatorAuthorityFramesTest/v1", "ok": ok,
            "tests": result.testsRun, "coldStarts": 1 if ok else 0,
            "oldCommit": migration.OLD_COMMIT, "targetCommit": migration.TARGET_COMMIT,
            "liveStateMounted": False, "providerRequests": 0}, sort_keys=True))
        raise SystemExit(0 if ok else 1)
    else:
        raise SystemExit("migration fixture invocation refused")
