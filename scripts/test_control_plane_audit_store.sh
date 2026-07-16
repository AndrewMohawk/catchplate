#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
ADMIN_TOKEN="${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}"
DATA_PLANE_TOKEN="${SERVERWARE_DATA_PLANE_AUDIT_TOKEN:-dev-audit-ingest-token}"

python3 - "$BASE" "$ADMIN_TOKEN" "$DATA_PLANE_TOKEN" <<'PY'
import concurrent.futures
import hashlib
import json
import sqlite3
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from serverware import db

base = sys.argv[1].rstrip("/")
admin_token = sys.argv[2]
data_plane_token = sys.argv[3]
marker = f"pg-audit-{time.time_ns()}"
event_count = 48


def verify_streaming_contract() -> None:
    rows = []
    previous_hash = None
    for index in range(1301):
        row = {
            "id": f"audit-{index}",
            "event_type": "test.audit.streaming",
            "actor_type": "test",
            "actor_id": None,
            "event_json": json.dumps({"index": index}, separators=(",", ":"), sort_keys=True),
            "prev_event_hash": previous_hash,
            "created_at": f"2026-01-01T00:00:{index % 60:02d}+00:00",
        }
        row["event_hash"] = db._audit_hash(
            event_id=row["id"],
            event_type=row["event_type"],
            actor_type=row["actor_type"],
            actor_id=row["actor_id"],
            event_json=row["event_json"],
            prev_event_hash=row["prev_event_hash"],
            created_at=row["created_at"],
        )
        rows.append(row)
        previous_hash = row["event_hash"]

    class FakeCursor:
        def __init__(self, values: list[dict], *, count_cursor: bool = False):
            self.values = values
            self.count_cursor = count_cursor
            self.position = 0
            self.fetch_sizes: list[int] = []
            self.queries: list[str] = []
            self.size_limit: int | None = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query: str, params: dict | None = None) -> None:
            self.queries.append(" ".join(query.split()))
            if self.count_cursor and params and "limit" in params:
                self.size_limit = int(params["limit"])
            if not self.count_cursor and params and "limit" in params:
                self.values = self.values[: int(params["limit"])]

        def fetchone(self) -> dict:
            assert self.count_cursor
            if "MAX(event_json_bytes)" in self.queries[-1]:
                selected = rows if self.size_limit is None else rows[: self.size_limit]
                return {
                    "max_bytes": max(
                        (len(row["event_json"].encode("utf-8")) for row in selected),
                        default=0,
                    )
                }
            return {"count": len(rows)}

        def fetchmany(self, size: int) -> list[dict]:
            assert not self.count_cursor
            self.fetch_sizes.append(size)
            batch = self.values[self.position : self.position + size]
            self.position += len(batch)
            return batch

        def fetchall(self):
            raise AssertionError("audit verification must not fetch the entire chain")

    class FakeConnection:
        def __init__(self):
            self.stream_cursor: FakeCursor | None = None
            self.count_cursor: FakeCursor | None = None
            self.named_cursor: str | None = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self, name: str | None = None) -> FakeCursor:
            if name is None:
                self.count_cursor = FakeCursor(rows, count_cursor=True)
                return self.count_cursor
            self.named_cursor = name
            self.stream_cursor = FakeCursor(list(rows))
            return self.stream_cursor

    connections: list[FakeConnection] = []

    def connect() -> FakeConnection:
        connection = FakeConnection()
        connections.append(connection)
        return connection

    original_uses_postgres = db.audit_uses_postgres
    original_connect = db._audit_pg_connect
    db.audit_uses_postgres = lambda: True
    db._audit_pg_connect = connect
    try:
        batch_size = db._AUDIT_VERIFY_BATCH_SIZE
        full = db.verify_audit_chain()
        limited_one = db.verify_audit_chain(limit=1)
        limited_boundary = db.verify_audit_chain(limit=batch_size)
        limited_next_batch = db.verify_audit_chain(limit=batch_size + 1)
        limited_exact = db.verify_audit_chain(limit=len(rows))
        limited_over = db.verify_audit_chain(limit=len(rows) + 10)
    finally:
        db.audit_uses_postgres = original_uses_postgres
        db._audit_pg_connect = original_connect

    assert full["ok"] is True and full["complete"] is True and full["count"] == len(rows), full
    assert full["head"] == rows[-1]["event_hash"], full
    for result, expected_count, complete in (
        (limited_one, 1, False),
        (limited_boundary, batch_size, False),
        (limited_next_batch, batch_size + 1, False),
        (limited_exact, len(rows), True),
        (limited_over, len(rows), True),
    ):
        assert result["ok"] is True and result["complete"] is complete, result
        assert result["count"] == expected_count and result["total"] == len(rows), result
        assert result["head"] == rows[expected_count - 1]["event_hash"], result
    assert all(connection.named_cursor == "serverware_audit_verify" for connection in connections)
    assert all(
        connection.count_cursor is not None
        and connection.count_cursor.queries[0]
        == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
        and connection.count_cursor.queries[1].startswith("SELECT COUNT(*)")
        and "MAX(event_json_bytes)" in connection.count_cursor.queries[2]
        and (
            connection.count_cursor.size_limit is None
            or "LIMIT %(limit)s" in connection.count_cursor.queries[2]
        )
        for connection in connections
    )
    assert all(
        connection.stream_cursor is not None
        and connection.stream_cursor.fetch_sizes
        and max(connection.stream_cursor.fetch_sizes) == db._AUDIT_VERIFY_BATCH_SIZE
        for connection in connections
    )

    empty = db._verify_audit_rows(
        FakeCursor([]),
        total=0,
        selected_count=0,
        batch_size=db._AUDIT_VERIFY_BATCH_SIZE,
        backend="postgres",
        ha=True,
    )
    assert empty == {
        "backend": "postgres",
        "ha": True,
        "serial_append": "pg_advisory_xact_lock",
        "ok": True,
        "count": 0,
        "total": 0,
        "complete": True,
        "head": None,
    }, empty

    corrupt_previous = [dict(row) for row in rows]
    corrupt_previous[batch_size]["prev_event_hash"] = "sha256:" + "0" * 64
    prefix = db._verify_audit_rows(
        FakeCursor(corrupt_previous[:batch_size]),
        total=len(rows),
        selected_count=batch_size,
        batch_size=batch_size,
        backend="postgres",
        ha=True,
    )
    assert prefix["ok"] is True and prefix["complete"] is False, prefix
    previous_failure = db._verify_audit_rows(
        FakeCursor(corrupt_previous[: batch_size + 1]),
        total=len(rows),
        selected_count=batch_size + 1,
        batch_size=batch_size,
        backend="postgres",
        ha=True,
    )
    assert previous_failure["error"] == "prev_hash_mismatch" and previous_failure["index"] == batch_size, previous_failure

    corrupt_hash = [dict(row) for row in rows[: batch_size + 1]]
    corrupt_hash[batch_size]["event_hash"] = "sha256:" + "f" * 64
    hash_failure = db._verify_audit_rows(
        FakeCursor(corrupt_hash),
        total=len(rows),
        selected_count=batch_size + 1,
        batch_size=batch_size,
        backend="postgres",
        ha=True,
    )
    assert hash_failure["error"] == "event_hash_mismatch" and hash_failure["index"] == batch_size, hash_failure

    short_failure = db._verify_audit_rows(
        FakeCursor(rows[:9]),
        total=10,
        selected_count=10,
        batch_size=batch_size,
        backend="postgres",
        ha=True,
    )
    assert short_failure["error"] == "row_count_mismatch" and short_failure["count"] == 9, short_failure

    oversized = dict(rows[0])
    oversized["event_json"] = "x" * (db._AUDIT_EVENT_JSON_STORED_MAX_BYTES + 1)
    oversized_failure = db._verify_audit_rows(
        FakeCursor([oversized]),
        total=1,
        selected_count=1,
        batch_size=1,
        backend="postgres",
        ha=True,
    )
    assert oversized_failure["error"] == "event_size_exceeded" and oversized_failure["index"] == 0, oversized_failure
    try:
        db.validate_audit_event(
            {"value": "x" * (db._AUDIT_EVENT_JSON_WRITE_MAX_BYTES + 1)}
        )
    except db.AuditStoreError:
        pass
    else:
        raise AssertionError("oversized canonical audit event was accepted for storage")

    original_backend = db.AUDIT_STORE_BACKEND
    original_metadata_backend = db.METADATA_STORE_BACKEND
    original_db_path = db.DB_PATH
    original_recovery_witness_path = db.WEBAUTHN_RECOVERY_WITNESS_PATH
    original_ensure_data_dirs = db.ensure_data_dirs
    try:
        with tempfile.TemporaryDirectory() as tmp:
            db.AUDIT_STORE_BACKEND = "sqlite"
            db.METADATA_STORE_BACKEND = "sqlite"
            db.DB_PATH = Path(tmp) / "legacy-audit.sqlite3"
            db.WEBAUTHN_RECOVERY_WITNESS_PATH = Path(tmp) / "recovery-witness.sqlite3"
            db.ensure_data_dirs = lambda: None
            connection = sqlite3.connect(db.DB_PATH)
            connection.executescript(
                """
                CREATE TABLE audit_events (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    actor_id TEXT,
                    event_json TEXT NOT NULL,
                    prev_event_hash TEXT,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            legacy_rows = []
            previous = None
            for row_id, event_json in (
                ("valid-prefix", '{"value":1}'),
                ("oversized-legacy-suffix", "x" * (db._AUDIT_EVENT_JSON_STORED_MAX_BYTES + 1)),
            ):
                created_at = "2026-01-01T00:00:00+00:00"
                event_hash = db._audit_hash(
                    event_id=row_id,
                    event_type="test.audit.legacy",
                    actor_type="test",
                    actor_id=None,
                    event_json=event_json,
                    prev_event_hash=previous,
                    created_at=created_at,
                )
                legacy_rows.append(
                    (
                        row_id,
                        "test.audit.legacy",
                        "test",
                        None,
                        event_json,
                        previous,
                        event_hash,
                        created_at,
                    )
                )
                previous = event_hash
            connection.executemany(
                "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                legacy_rows,
            )
            connection.commit()
            connection.close()

            original_grant_store_init = db.grants.init_grant_store
            db.grants.init_grant_store = lambda: None
            try:
                try:
                    db.init_db()
                except db.AuditStoreError as exc:
                    assert "event_size_exceeded" in str(exc), exc
                else:
                    raise AssertionError(
                        "audit migration continued over an oversized invalid legacy chain"
                    )
            finally:
                db.grants.init_grant_store = original_grant_store_init
            with sqlite3.connect(db.DB_PATH) as connection:
                stored_rows = connection.execute(
                    "SELECT id, event_json, event_hash FROM audit_events ORDER BY rowid"
                ).fetchall()
                assert stored_rows == [
                    (row[0], row[4], row[6]) for row in legacy_rows
                ], stored_rows
                migration_table = connection.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'serverware_store_migrations'"
                ).fetchone()
                if migration_table:
                    completed = connection.execute(
                        "SELECT COUNT(*) FROM serverware_store_migrations "
                        "WHERE migration = ? AND version = ?",
                        (
                            db._AUDIT_STORAGE_REDACTION_MIGRATION,
                            db._STORAGE_REDACTION_MIGRATION_VERSION,
                        ),
                    ).fetchone()[0]
                    assert completed == 0, completed

            db.DB_PATH = Path(tmp) / "snapshot-audit.sqlite3"
            seed_event_json = '{"snapshot":1}'
            seed_created_at = "2026-01-01T00:00:00+00:00"
            seed_hash = db._audit_hash(
                event_id="snapshot-seed",
                event_type="test.audit.snapshot",
                actor_type="test",
                actor_id=None,
                event_json=seed_event_json,
                prev_event_hash=None,
                created_at=seed_created_at,
            )
            connection = sqlite3.connect(db.DB_PATH)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE audit_events (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    actor_id TEXT,
                    event_json TEXT NOT NULL,
                    encrypted_canonical_event_json TEXT,
                    storage_format_version INTEGER,
                    prev_event_hash TEXT,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE serverware_store_migrations (
                    migration TEXT PRIMARY KEY,
                    version BIGINT NOT NULL,
                    applied_at TEXT NOT NULL
                );
                """
            )
            connection.execute(
                "INSERT INTO audit_events "
                "(id, event_type, actor_type, actor_id, event_json, "
                "prev_event_hash, event_hash, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "snapshot-seed",
                    "test.audit.snapshot",
                    "test",
                    None,
                    seed_event_json,
                    None,
                    seed_hash,
                    seed_created_at,
                ),
            )
            connection.commit()
            connection.close()

            snapshot_append = {}
            original_connect = db.connect

            class SnapshotCursor:
                def __init__(self, cursor):
                    self.cursor = cursor

                def fetchone(self):
                    row = self.cursor.fetchone()
                    if not snapshot_append:
                        event_json = '{"snapshot":2}'
                        created_at = "2026-01-01T00:00:01+00:00"
                        event_hash = db._audit_hash(
                            event_id="snapshot-concurrent",
                            event_type="test.audit.snapshot",
                            actor_type="test",
                            actor_id=None,
                            event_json=event_json,
                            prev_event_hash=seed_hash,
                            created_at=created_at,
                        )
                        writer = sqlite3.connect(db.DB_PATH)
                        writer.execute(
                            "INSERT INTO audit_events "
                            "(id, event_type, actor_type, actor_id, event_json, "
                            "prev_event_hash, event_hash, created_at) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                "snapshot-concurrent",
                                "test.audit.snapshot",
                                "test",
                                None,
                                event_json,
                                seed_hash,
                                event_hash,
                                created_at,
                            ),
                        )
                        writer.commit()
                        writer.close()
                        snapshot_append.update(event_hash=event_hash)
                    return row

            class SnapshotConnection:
                def __init__(self, connection):
                    self.connection = connection

                def __enter__(self):
                    self.connection.__enter__()
                    return self

                def __exit__(self, *args):
                    return self.connection.__exit__(*args)

                def execute(self, query, params=()):
                    cursor = self.connection.execute(query, params)
                    if query.strip().startswith("SELECT COUNT(*)"):
                        return SnapshotCursor(cursor)
                    return cursor

            db.connect = lambda: SnapshotConnection(original_connect())
            try:
                sqlite_snapshot = db.verify_audit_chain()
            finally:
                db.connect = original_connect
            assert sqlite_snapshot["ok"] is True and sqlite_snapshot["complete"] is True, sqlite_snapshot
            assert sqlite_snapshot["count"] == 1 and sqlite_snapshot["total"] == 1, sqlite_snapshot
            assert sqlite_snapshot["head"] == seed_hash, sqlite_snapshot
            with sqlite3.connect(db.DB_PATH) as actual:
                assert actual.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 2

            db.DB_PATH = Path(tmp) / "atomic-batch.sqlite3"
            connection = sqlite3.connect(db.DB_PATH)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE audit_events (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    actor_id TEXT,
                    event_json TEXT NOT NULL,
                    encrypted_canonical_event_json TEXT,
                    storage_format_version INTEGER,
                    prev_event_hash TEXT,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE serverware_store_migrations (
                    migration TEXT PRIMARY KEY,
                    version BIGINT NOT NULL,
                    applied_at TEXT NOT NULL
                );
                CREATE TRIGGER reject_second_audit_event
                BEFORE INSERT ON audit_events
                WHEN NEW.event_type = 'test.audit.reject'
                BEGIN
                    SELECT RAISE(ABORT, 'injected audit storage failure');
                END;
                """
            )
            connection.commit()
            connection.close()
            try:
                db.record_audit_event_batch(
                    [
                        ("test.audit.accept", {"index": 0}),
                        ("test.audit.reject", {"index": 1}),
                    ],
                    actor_type="test",
                    actor_id="atomic-batch-test",
                )
            except sqlite3.IntegrityError as exc:
                assert "injected audit storage failure" in str(exc), exc
            else:
                raise AssertionError("audit storage failure did not abort the batch")
            with sqlite3.connect(db.DB_PATH) as actual:
                assert actual.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0
    finally:
        db.AUDIT_STORE_BACKEND = original_backend
        db.METADATA_STORE_BACKEND = original_metadata_backend
        db.DB_PATH = original_db_path
        db.WEBAUTHN_RECOVERY_WITNESS_PATH = original_recovery_witness_path
        db.ensure_data_dirs = original_ensure_data_dirs


verify_streaming_contract()


def request_json(path: str, *, method: str = "GET", headers: dict[str, str] | None = None, payload: dict | None = None) -> dict | list:
    body = None
    request_headers = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{base}{path}", data=body, method=method, headers=request_headers)
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.loads(response.read())


admin_headers = {"X-Serverware-Admin-Token": admin_token}
data_plane_headers = {"X-Serverware-Data-Plane-Token": data_plane_token}


def producer_event_id(namespace: str, index: int) -> str:
    value = hashlib.sha256(f"{namespace}:{index}".encode("utf-8")).hexdigest()
    return f"sha256:{value}"


partial_marker = f"audit-oversized-{time.time_ns()}"
oversized_payload = {
    "events": [
        {
            "eventId": producer_event_id(partial_marker, 0),
            "event_type": "data_plane.audit_store.must_not_commit",
            "event": {"marker": partial_marker, "index": 0},
        },
        {
            "eventId": producer_event_id(partial_marker, 1),
            "event_type": "data_plane.audit_store.oversized",
            "event": {"marker": partial_marker, "value": "é" * 350_000},
        },
    ]
}
oversized_body = json.dumps(
    oversized_payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False
).encode("utf-8")
oversized_request = urllib.request.Request(
    f"{base}/api/data-plane/audit",
    data=oversized_body,
    method="POST",
    headers={**data_plane_headers, "Content-Type": "application/json"},
)
try:
    urllib.request.urlopen(oversized_request, timeout=15)
except urllib.error.HTTPError as exc:
    assert exc.code == 413, (exc.code, exc.read())
else:
    raise AssertionError("oversized audit batch was accepted")
latest_after_oversized = request_json("/api/audit?limit=500", headers=admin_headers)
assert all(
    (item.get("event") or {}).get("marker") != partial_marker
    for item in latest_after_oversized
), latest_after_oversized

status = request_json("/api/audit/store/status", headers=admin_headers)
assert status["backend"] == "postgres", status
assert status["ha"] is True, status
assert status["serial_append"] == "pg_advisory_xact_lock", status

before = request_json("/api/audit/verify", headers=admin_headers)
assert before["ok"] is True and before["complete"] is True, before
assert before["backend"] == "postgres" and before["ha"] is True, before
start_total = int(before["total"])


def post_event(index: int) -> dict:
    payload = {
        "events": [
            {
                "eventId": producer_event_id(marker, index),
                "event_type": "data_plane.audit_store.concurrent_append",
                "event": {
                    "marker": marker,
                    "index": index,
                    "created_by": "test_control_plane_audit_store",
                },
            }
        ]
    }
    return request_json("/api/data-plane/audit", method="POST", headers=data_plane_headers, payload=payload)


with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
    results = list(pool.map(post_event, range(event_count)))

assert all(item.get("ok") is True and item.get("accepted") == 1 for item in results), results

deadline = time.time() + 20
last_verify = {}
latest_events: list[dict] = []
while time.time() < deadline:
    last_verify = request_json("/api/audit/verify", headers=admin_headers)
    latest_events = request_json("/api/audit?limit=500", headers=admin_headers)
    found = {
        int((item.get("event") or {}).get("index"))
        for item in latest_events
        if (item.get("event") or {}).get("marker") == marker
    }
    if (
        last_verify.get("ok") is True
        and last_verify.get("complete") is True
        and int(last_verify.get("total") or 0) >= start_total + event_count
        and found == set(range(event_count))
    ):
        print(
            json.dumps(
                {
                    "ok": True,
                    "audit_store": "postgres",
                    "ha": True,
                    "serial_append": last_verify.get("serial_append"),
                    "concurrent_events": event_count,
                    "start_total": start_total,
                    "end_total": int(last_verify.get("total") or 0),
                },
                sort_keys=True,
            )
        )
        break
    time.sleep(0.25)
else:
    raise SystemExit(
        f"postgres audit chain did not contain all concurrent events; verify={last_verify} marker={marker}"
    )
PY

docker compose exec -T serverware python - <<'PY'
import concurrent.futures
import uuid

from psycopg import sql
from psycopg.errors import CheckViolation

from serverware import db


original_connect = db._audit_pg_connect
state = {"appended": None, "count_seen": False}


class SnapshotCursor:
    def __init__(self, cursor, *, count_cursor: bool):
        self.cursor = cursor
        self.count_cursor = count_cursor
        self.last_query = ""

    def __enter__(self):
        self.cursor.__enter__()
        return self

    def __exit__(self, *args):
        return self.cursor.__exit__(*args)

    def execute(self, query, params=None):
        self.last_query = " ".join(query.split())
        if params is None:
            self.cursor.execute(query)
        else:
            self.cursor.execute(query, params)
        return self

    def fetchone(self):
        row = self.cursor.fetchone()
        if (
            self.count_cursor
            and self.last_query.startswith("SELECT COUNT(*)")
            and not state["count_seen"]
        ):
            state["count_seen"] = True
            db._audit_pg_connect = original_connect
            try:
                state["appended"] = db.record_audit_event(
                    "test.audit.snapshot.concurrent",
                    {"source": "test_control_plane_audit_store"},
                    actor_type="test",
                    actor_id="snapshot-test",
                )
            finally:
                db._audit_pg_connect = snapshot_connect
        return row

    def fetchmany(self, size):
        return self.cursor.fetchmany(size)


class SnapshotConnection:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        self.connection.__enter__()
        return self

    def __exit__(self, *args):
        return self.connection.__exit__(*args)

    def cursor(self, name=None):
        cursor = self.connection.cursor() if name is None else self.connection.cursor(name=name)
        return SnapshotCursor(cursor, count_cursor=name is None)


def snapshot_connect():
    return SnapshotConnection(original_connect())


db._audit_pg_connect = snapshot_connect
try:
    snapshot = db.verify_audit_chain()
finally:
    db._audit_pg_connect = original_connect

appended = state["appended"]
assert appended is not None, state
assert snapshot["ok"] is True and snapshot["complete"] is True, snapshot
assert snapshot["head"] != appended["event_hash"], (snapshot, appended)
with original_connect() as connection:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT COUNT(*)::bigint AS count, "
            "MAX(sequence) FILTER (WHERE id = %s)::bigint AS appended_sequence "
            "FROM serverware_audit_events",
            (appended["id"],),
        )
        current = cursor.fetchone()
        current_total = int(current["count"])
        appended_sequence = int(current["appended_sequence"])
assert appended_sequence > int(snapshot["total"]), (snapshot, appended_sequence)
assert current_total >= int(snapshot["total"]) + 1, (snapshot, current_total)

schema = "audit_migration_test_" + uuid.uuid4().hex
oversized_legacy_json = "x" * (db._AUDIT_EVENT_JSON_STORED_MAX_BYTES + 1)
with original_connect() as connection:
    with connection.cursor() as cursor:
        cursor.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        cursor.execute(
            sql.SQL(
                """
                CREATE TABLE {}.serverware_audit_events (
                    sequence BIGSERIAL PRIMARY KEY,
                    id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    actor_id TEXT,
                    event_json TEXT NOT NULL,
                    prev_event_hash TEXT,
                    event_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                )
                """
            ).format(sql.Identifier(schema))
        )
        cursor.execute(
            sql.SQL(
                """
                INSERT INTO {}.serverware_audit_events (
                    id, event_type, actor_type, actor_id, event_json,
                    prev_event_hash, event_hash, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """
            ).format(sql.Identifier(schema)),
            (
                "oversized-legacy-row",
                "test.audit.legacy",
                "test",
                None,
                oversized_legacy_json,
                None,
                "sha256:" + "2" * 64,
                "2026-01-01T00:00:00+00:00",
            ),
        )


def migration_connect():
    connection = original_connect()
    connection.execute(
        sql.SQL("SET search_path TO {}").format(sql.Identifier(schema))
    )
    return connection


db._audit_pg_connect = migration_connect
try:
    def rejected_migration(_index):
        try:
            db.init_audit_store()
        except db.AuditStoreError as exc:
            assert "event_size_exceeded" in str(exc), exc
            return "rejected"
        raise AssertionError(
            "PostgreSQL audit migration continued over an oversized invalid legacy chain"
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(rejected_migration, range(2))) == [
            "rejected",
            "rejected",
        ]
    with migration_connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*)::bigint AS count,
                       bool_and(NOT convalidated) AS all_unvalidated
                FROM pg_constraint
                WHERE conrelid = 'serverware_audit_events'::regclass
                  AND conname = 'serverware_audit_events_event_json_size'
                """
            )
            constraint = cursor.fetchone()
            assert int(constraint["count"]) == 1 and constraint["all_unvalidated"] is True, constraint
            cursor.execute(
                "SELECT id, event_json FROM serverware_audit_events"
            )
            stored = cursor.fetchone()
            assert stored == {
                "id": "oversized-legacy-row",
                "event_json": oversized_legacy_json,
            }, stored
            cursor.execute(
                "SELECT COUNT(*)::bigint AS count FROM serverware_store_migrations "
                "WHERE migration = %s AND version = %s",
                (
                    db._AUDIT_STORAGE_REDACTION_MIGRATION,
                    db._STORAGE_REDACTION_MIGRATION_VERSION,
                ),
            )
            assert int(cursor.fetchone()["count"]) == 0
    try:
        with migration_connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO serverware_audit_events (
                        id, event_type, actor_type, actor_id, event_json,
                        prev_event_hash, event_hash, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        "oversized-new-row",
                        "test.audit.legacy",
                        "test",
                        None,
                        oversized_legacy_json,
                        None,
                        "sha256:" + "3" * 64,
                        "2026-01-01T00:00:01+00:00",
                    ),
                )
    except CheckViolation:
        pass
    else:
        raise AssertionError("PostgreSQL migration accepted a new oversized audit row")
finally:
    db._audit_pg_connect = original_connect
    with original_connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
            )

print(
    {
        "ok": True,
        "postgres_repeatable_read_snapshot": "pass",
        "postgres_concurrent_invalid_migration_rejected": "pass",
        "snapshot_total": snapshot["total"],
    }
)
PY
