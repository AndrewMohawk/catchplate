#!/usr/bin/env python3
"""Offline SQLite setup characterization; no production optimization claim.

--retained-sqlite copies only a stopped DB and its exact optional WAL/SHM files
to temporary storage. Measurements concern fresh-handle schema work there, not
the original filesystem, deployed contention, or workload acceptance. The
0.1-second busy timeout is diagnostic-only; production remains 10 seconds.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, nullcontext
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware.authority_store.metadata_schema import configure_sqlite_metadata_connection
from serverware.operator_google_cleanup_store import configure_connection

TIMEOUT = 0.1
STRATEGIES = ("repeated_assignment", "read_mode_first")
SERIALIZED = "serialized_assignment"
MAX_FILE_BYTES = 128 * 1024 * 1024


def mode(conn, sql, statements):
    statements.append(sql)
    with closing(conn.execute(sql)) as cursor:
        rows = cursor.fetchall()
    if len(rows) != 1 or len(rows[0]) != 1 or not isinstance(rows[0][0], str):
        raise AssertionError("unexpected journal-mode result shape")
    return rows[0][0]


def fresh_setup(path, strategy, barrier=None, setup_gate=None):
    if strategy not in (*STRATEGIES, SERIALIZED) or (strategy == SERIALIZED) != (setup_gate is not None):
        raise ValueError("unknown characterization strategy")
    if barrier is not None:
        barrier.wait(timeout=5)
    started, cpu = time.perf_counter_ns(), time.thread_time_ns()
    statements, connection = [], None
    result = {"strategy": strategy, "outcome": "error", "mode": None, "errorClass": None}
    try:
        connection = sqlite3.connect(path, timeout=TIMEOUT)
        # The same two registration callbacks used by db.connect, with no SQL
        # or prewarming query before the mode statement under investigation.
        configure_sqlite_metadata_connection(connection)
        configure_connection(connection)
        connection.row_factory = sqlite3.Row
        # Supplemental characterization only: serialize first SQL setup, not
        # connection ownership, later queries, transactions or close. Include
        # gate wait in wall time so serialization cannot hide queued work.
        with setup_gate if setup_gate is not None else nullcontext():
            current = mode(connection, "PRAGMA journal_mode", statements) if strategy == "read_mode_first" else None
            if current != "wal":
                current = mode(connection, "PRAGMA journal_mode=WAL", statements)
            connection.execute("PRAGMA foreign_keys=ON").close()
        result.update(outcome="returned", mode=current)
    except sqlite3.Error as error:
        # Deliberately no exception text, SQL schema, row data, or file path.
        result["errorClass"] = type(error).__name__ if type(error) in (
            sqlite3.OperationalError, sqlite3.DatabaseError) else "SQLiteError"
    finally:
        if connection is not None:
            connection.close()
    result.update(wallNs=time.perf_counter_ns() - started,
        threadCpuNs=time.thread_time_ns() - cpu, modeStatements=statements)
    return result


def batch(path, strategy, callers):
    if callers not in (1, 3):
        raise ValueError("characterization caller count refused")
    started, cpu = time.perf_counter_ns(), time.process_time_ns()
    barrier = threading.Barrier(callers) if callers > 1 else None
    setup_gate = threading.Lock() if strategy == SERIALIZED else None
    with ThreadPoolExecutor(max_workers=callers) as pool:
        futures = [pool.submit(fresh_setup, path, strategy, barrier, setup_gate) for _ in range(callers)]
        calls = [future.result(timeout=5) for future in futures]
    return {"strategy": strategy, "callers": callers, "calls": calls,
        "wallNs": time.perf_counter_ns() - started, "processCpuNs": time.process_time_ns() - cpu}


def schema_size(path):
    with closing(sqlite3.connect(path, timeout=TIMEOUT)) as conn:
        objects, sql_bytes = conn.execute(
            "SELECT count(*), coalesce(sum(length(CAST(sql AS BLOB))),0) FROM sqlite_master").fetchone()
        current = conn.execute("PRAGMA journal_mode").fetchone()[0]
    return {"objects": objects, "sqlBytes": sql_bytes, "journalMode": current}


def fingerprint(source):
    files = {}
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(source) + suffix)
        try:
            info = path.lstat()
        except FileNotFoundError:
            if not suffix:
                raise ValueError("stopped SQLite database missing") from None
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 <= info.st_size <= MAX_FILE_BYTES:
            raise ValueError("stopped SQLite file metadata refused")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        files[suffix] = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, digest.digest())
    return files


def retained_matrix(source, *, serialized_only=False):
    source = Path(source)
    if not source.is_absolute() or source.resolve() != source:
        raise ValueError("absolute non-symlink stopped SQLite path required")
    before, observations, schemas = fingerprint(source), [], []
    strategies = (SERIALIZED,) if serialized_only else STRATEGIES
    with tempfile.TemporaryDirectory(prefix="serverware-wal-characterization-") as directory:
        for round_number in (1, 2):
            # Reverse ordering reduces a simple first-strategy cache bias; this
            # is still a small characterization, not a statistical benchmark.
            for strategy in strategies if round_number == 1 else reversed(strategies):
                for callers in (1, 3):
                    trial = Path(directory) / f"trial-{round_number}-{strategy}-{callers}"
                    trial.mkdir(mode=0o700)
                    path = trial / "serverware.sqlite3"
                    for suffix in before:
                        shutil.copyfile(Path(str(source) + suffix), Path(str(path) + suffix))
                        Path(str(path) + suffix).chmod(0o600)
                    # Introspection occurs on a different handle. Each measured
                    # handle still reaches its first SQL at the mode statement.
                    schemas.append(schema_size(path))
                    observations.append({"round": round_number, **batch(path, strategy, callers)})
    if fingerprint(source) != before:
        raise ValueError("stopped SQLite input changed during characterization")
    if any(item != schemas[0] for item in schemas):
        raise ValueError("copied SQLite schema or mode diverged between trials")
    return {"schema": "serverware.privateWalSetupCharacterization/v1", "sqliteVersion": sqlite3.sqlite_version,
        "scope": "temporary-copy-fresh-connection-not-original-filesystem-or-workload",
        "busyTimeoutSeconds": TIMEOUT, "schemaSize": schemas[0], "sourceUnchanged": True,
        "copiedSuffixes": sorted(before), "observations": observations}


class WalConnectionSetupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="serverware-wal-controls-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "synthetic.sqlite3"
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("CREATE TABLE synthetic (id INTEGER PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO synthetic VALUES(1,'synthetic')")

    def returned(self, observation):
        self.assertEqual(observation["outcome"], "returned")
        self.assertEqual(observation["mode"], "wal")
        self.assertIsNone(observation["errorClass"])
        self.assertGreaterEqual(observation["wallNs"], 0)
        self.assertGreaterEqual(observation["threadCpuNs"], 0)

    def test_real_delete_transition_and_fresh_replaced_path_do_not_cache_mode(self):
        for strategy in STRATEGIES:
            with self.subTest(strategy=strategy):
                with closing(sqlite3.connect(self.path)) as conn:
                    self.assertEqual(conn.execute("PRAGMA journal_mode=DELETE").fetchone()[0], "delete")
                first = fresh_setup(self.path, strategy)
                self.returned(first)
                expected = ["PRAGMA journal_mode", "PRAGMA journal_mode=WAL"] if strategy == "read_mode_first" else ["PRAGMA journal_mode=WAL"]
                self.assertEqual(first["modeStatements"], expected)
                self.returned(fresh_setup(self.path, strategy))
        replacement = self.path.with_name("replacement.sqlite3")
        with closing(sqlite3.connect(replacement)) as conn:
            conn.execute("CREATE TABLE replacement (id INTEGER)")
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "delete")
        replacement.replace(self.path)
        fresh = fresh_setup(self.path, "read_mode_first")
        self.returned(fresh)
        self.assertEqual(fresh["modeStatements"], ["PRAGMA journal_mode", "PRAGMA journal_mode=WAL"])

    def test_held_wal_reader_writer_and_schema_transactions_report_without_speed_assumptions(self):
        self.returned(fresh_setup(self.path, "repeated_assignment"))
        observations = []
        for condition in ("reader", "writer", "schema"):
            with closing(sqlite3.connect(self.path, timeout=TIMEOUT)) as holder:
                holder.execute("BEGIN" if condition == "reader" else "BEGIN IMMEDIATE")
                holder.execute("SELECT * FROM synthetic").fetchall()
                if condition == "writer":
                    holder.execute("UPDATE synthetic SET value='uncommitted' WHERE id=1")
                elif condition == "schema":
                    holder.execute("CREATE TABLE uncommitted_schema (id INTEGER)")
                try:
                    if condition != "reader":
                        with closing(sqlite3.connect(self.path, timeout=0)) as competitor:
                            with self.assertRaises(sqlite3.OperationalError):
                                competitor.execute("BEGIN IMMEDIATE")
                    for strategy in STRATEGIES:
                        observed = batch(self.path, strategy, 3)
                        for call in observed["calls"]:
                            self.assertIn(call["outcome"], {"returned", "error"})
                            if call["outcome"] == "returned":
                                self.returned(call)
                            else:
                                self.assertIn(call["errorClass"], {"OperationalError", "DatabaseError", "SQLiteError"})
                                self.assertIsNone(call["mode"])
                        observations.append({"condition": condition, **observed})
                finally:
                    holder.rollback()
            for strategy in STRATEGIES:
                self.returned(fresh_setup(self.path, strategy))
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(conn.execute("SELECT value FROM synthetic").fetchone()[0], "synthetic")
            self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name='uncommitted_schema'").fetchone())
        print(json.dumps({"schema": "serverware.privateWalHeldLockCharacterization/v1",
            "sqliteVersion": sqlite3.sqlite_version, "observations": observations}, sort_keys=True))

    def test_exclusive_read_failure_does_not_fall_through_or_mutate_input_copy(self):
        with closing(sqlite3.connect(self.path)) as holder:
            holder.execute("BEGIN EXCLUSIVE")  # Genuine DELETE-mode exclusive lock.
            try:
                for strategy in STRATEGIES:
                    observed = fresh_setup(self.path, strategy)
                    self.assertEqual(observed["outcome"], "error")
                    self.assertIsNone(observed["mode"])
                    self.assertEqual(observed["errorClass"], "OperationalError")
                    self.assertEqual(observed["modeStatements"],
                        ["PRAGMA journal_mode"] if strategy == "read_mode_first" else ["PRAGMA journal_mode=WAL"])
            finally:
                holder.rollback()
        before = fingerprint(self.path)
        report = retained_matrix(self.path)
        self.assertEqual(fingerprint(self.path), before)
        self.assertTrue(report["sourceUnchanged"])
        self.assertEqual(report["schemaSize"]["journalMode"], "delete")
        self.assertEqual(len(report["observations"]), 8)
        self.assertEqual(sum(len(item["calls"]) for item in report["observations"]), 16)

    def test_serialized_characterization_preserves_wal_statement_and_returns_all_callers(self):
        self.returned(fresh_setup(self.path, "repeated_assignment"))
        observed = batch(self.path, SERIALIZED, 3)
        self.assertEqual(len(observed["calls"]), 3)
        for call in observed["calls"]:
            self.returned(call)
            self.assertEqual(call["modeStatements"], ["PRAGMA journal_mode=WAL"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retained-sqlite", type=Path)
    parser.add_argument("--serialized-only", action="store_true")
    args, remaining = parser.parse_known_args()
    if args.retained_sqlite is not None:
        if remaining:
            parser.error("unexpected characterization arguments")
        print(json.dumps(retained_matrix(args.retained_sqlite, serialized_only=args.serialized_only), sort_keys=True))
    else:
        if args.serialized_only:
            parser.error("serialized characterization requires a stopped SQLite input")
        unittest.main(argv=[sys.argv[0], *remaining])
