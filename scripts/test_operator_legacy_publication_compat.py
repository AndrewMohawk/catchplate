#!/usr/bin/env python3
"""Run unchanged legacy crash oracles against explicit pre-catalog fixtures.

Only bootstrap/crash workers suppress the catalog metadata initializer, as the
existing workspace migration fixture does. Publication coordination, catalog
write refusal, SQLite, encryption, signing and crash hooks remain real. Recovery
uses the original unpatched worker and must activate the actual catalog.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_operator_demo_persistence as persistence
import test_operator_demo_revocation as revocation


def _assert_no_catalog(connection):
    assert not any(row[0].lower().startswith("operator_catalog_") for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")), "compatibility fixture is already catalog-versioned"


def _fixture_initializer(connection):
    # This is a fixture-version choice, never a schema.active/write-guard mock.
    _assert_no_catalog(connection)


def worker(kind, operation):
    if kind not in {"persistence", "revocation"} or operation not in {"bootstrap", "crash", "reopen"}:
        raise ValueError("unsupported compatibility fixture operation")
    original = persistence if kind == "persistence" else revocation
    if operation == "reopen":
        original.worker(operation)
        from serverware import operator_catalog_schema as schema
        assert schema.active(), "unpatched recovery did not activate the real catalog"
        return

    database = Path(os.environ["SERVERWARE_DATA_DIR"]) / "serverware.sqlite3"
    if operation == "bootstrap":
        assert not database.exists(), "legacy bootstrap requires fresh synthetic data"
    else:
        assert database.is_file(), "legacy crash requires its prior bootstrap fixture"
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
            _assert_no_catalog(connection)
            assert connection.execute("SELECT COUNT(*) FROM operator_demo_policy").fetchone()[0] == 1
    from serverware import operator_catalog_schema as schema
    with patch.object(schema, "initialize", _fixture_initializer):
        original.worker(operation)
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
        _assert_no_catalog(connection)


class LegacyPersistenceCrashTests(unittest.TestCase):
    setUp = persistence.OperatorDemoPersistenceTests.setUp
    run_worker = persistence.OperatorDemoPersistenceTests.run_worker
    test_process_exit_after_commit_recovers_policy_file_on_restart = (
        persistence.OperatorDemoPersistenceTests.test_process_exit_after_commit_recovers_policy_file_on_restart)

    def command(self, operation):
        return [sys.executable, "-B", str(Path(__file__).resolve()),
            "--legacy-worker", "persistence", operation]


class LegacyRevocationCrashTests(unittest.TestCase):
    setUp = persistence.OperatorDemoPersistenceTests.setUp
    test_process_crash_after_commit_recovers_without_second_revoke = (
        revocation.OperatorDemoRevocationTests.test_process_crash_after_commit_recovers_without_second_revoke)

    def run_worker(self, operation, expected=0):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()),
            "--legacy-worker", "revocation", operation], cwd=persistence.ROOT,
            env=self.environment, text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, expected, "\n".join(result.stderr.splitlines()[-40:]))
        return json.loads(result.stdout) if expected == 0 else None


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--legacy-worker":
        os.umask(0o077)
        worker(sys.argv[2], sys.argv[3])
    else:
        unittest.main(verbosity=2)
