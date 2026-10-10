#!/usr/bin/env python3
"""Pure projection and disposable SQLite checks; no app/config/live DB imports."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from serverware.db_common import audit_hash
from serverware import operator_notification_events as events

NOW = datetime(2026, 10, 10, 12, tzinfo=timezone.utc)
NOW_MS = int(NOW.timestamp() * 1000)
CREATED = (NOW - timedelta(seconds=4)).isoformat()
REQUESTED = (NOW - timedelta(seconds=5)).isoformat()
EXPIRES = (NOW + timedelta(seconds=60)).isoformat()
DIGEST = "sha256:" + "a" * 64
CANARY = "SYNTHETIC-NOTIFICATION-SECRET-DO-NOT-EXPORT"


class EventTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="serverware-notification-events-")
        self.path = Path(self.temp.name) / "test.sqlite3"
        self.writer = sqlite3.connect(self.path)
        self.writer.execute("PRAGMA journal_mode=WAL")
        self.writer.executescript("""
            CREATE TABLE audit_events(id TEXT PRIMARY KEY,event_type TEXT,actor_type TEXT,actor_id TEXT,
                event_json TEXT,storage_format_version INTEGER,encrypted_canonical_event_json TEXT,
                prev_event_hash TEXT,event_hash TEXT,created_at TEXT);
            CREATE TABLE approval_requests(id TEXT PRIMARY KEY,status TEXT,requested_at TEXT,
                route_id TEXT,method TEXT,expires_at TEXT,principal_id TEXT,credential_id TEXT,
                credential_version INTEGER,policy_hash TEXT,request_digest TEXT,operation_digest TEXT,
                grant_ttl_seconds INTEGER,grant_max_uses INTEGER,approver_policy_digest TEXT,url TEXT,
                canonical_request TEXT,redacted_display TEXT);
            CREATE TABLE control_plane_approvals(id TEXT PRIMARY KEY,status TEXT,requested_at TEXT,
                action TEXT,resource_id TEXT,payload_digest TEXT,requester_id TEXT,expires_at TEXT,request_json TEXT);
        """)

    def tearDown(self):
        self.writer.close()
        self.temp.cleanup()

    @contextmanager
    def reader(self, *, forbid_secrets=False):
        conn = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            if forbid_secrets:
                forbidden = {"canonical_request", "redacted_display", "request_json", "encrypted_canonical_event_json"}
                conn.set_authorizer(lambda operation, first, second, database, trigger:
                    sqlite3.SQLITE_DENY if operation == sqlite3.SQLITE_READ and second in forbidden else sqlite3.SQLITE_OK)
            yield conn
        finally:
            conn.close()

    def append(self, kind="data_plane.response.released", payload=None, *, raw=None, commit=True, actor=CANARY):
        identifier = str(uuid.uuid4())
        previous = self.writer.execute("SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1").fetchone()
        previous = previous[0] if previous else None
        raw = raw if raw is not None else json.dumps(payload or {}, separators=(",", ":"), sort_keys=True)
        digest = audit_hash(event_id=identifier, event_type=kind, actor_type="data-plane", actor_id=actor,
            event_json=raw, prev_event_hash=previous, created_at=CREATED)
        self.writer.execute("INSERT INTO audit_events VALUES(?,?,?,?,?,2,NULL,?,?,?)",
            (identifier, kind, "data-plane", actor, raw, previous, digest, CREATED))
        if commit:
            self.writer.commit()
        return identifier

    def read(self, cursor=events.EventCursor(), **kwargs):
        with self.reader() as conn:
            return events.read_batch(conn, cursor, now_epoch_ms=NOW_MS, **kwargs)

    def pending(self, *, control=False, jit=False):
        identifier, route = str(uuid.uuid4()), "operator." + str(uuid.uuid4())
        if control:
            payload = {"approval_id": identifier, "action": "credential.create", "resource_id": None,
                "payload_digest": DIGEST, "requester_id": CANARY, "expires_at": EXPIRES,
                "request": {"secret": CANARY, "body": {"token": CANARY}}}
            self.writer.execute("INSERT INTO control_plane_approvals VALUES(?,?,?,?,?,?,?,?,?)",
                (identifier, "pending", REQUESTED, payload["action"], None, DIGEST, CANARY, EXPIRES, CANARY))
            kind = "control_plane.approval.requested"
        else:
            url = "https://example.invalid/private/" + CANARY
            url_digest = "sha256:" + hashlib.sha256(url.encode()).hexdigest()
            payload = {"approval_request_id": identifier, "route_id": route, "method": "POST",
                "url_commitment": url_digest, "expires_at": EXPIRES}
            if jit:
                payload.update(principal_id="agent:operator-demo:" + str(uuid.uuid4()), credential_id=str(uuid.uuid4()),
                    credential_version=1, policy_hash=DIGEST, request_digest=DIGEST, operation_digest=None,
                    grant_ttl_seconds=60, grant_max_uses=1, approver_policy_digest=DIGEST)
            fields = ("route_id", "method", "expires_at", "principal_id", "credential_id", "credential_version",
                "policy_hash", "request_digest", "operation_digest", "grant_ttl_seconds", "grant_max_uses", "approver_policy_digest")
            self.writer.execute("INSERT INTO approval_requests VALUES(" + ",".join("?" for _ in range(18)) + ")",
                (identifier, "pending", REQUESTED, *(payload.get(key) for key in fields),
                    url_digest if jit else url, CANARY, CANARY))
            kind = "approval.requested"
        self.writer.commit()
        self.append(kind, payload)
        return identifier, payload

    def test_imports_and_closed_filters(self):
        for name in ("serverware.db", "serverware.config", "serverware.crypto", "serverware.app"):
            self.assertNotIn(name, sys.modules)
        self.assertEqual(events.AUDIT_EVENT_TYPES, tuple(sorted(set(events.AUDIT_EVENT_TYPES))))
        self.assertEqual(events.ACTION_EVENT_TYPES, tuple(sorted(set(events.ACTION_EVENT_TYPES))))
        self.assertTrue(set(events.ACTION_EVENT_TYPES) <= set(events.AUDIT_EVENT_TYPES))
        self.assertFalse(any(kind.startswith("notification.") for kind in events.AUDIT_EVENT_TYPES))

    def test_projection_drops_secrets_and_arbitrary_content(self):
        credential = str(uuid.uuid4())
        self.append(payload={"credential_ref": credential, "method": "GET", "upstream_status": 200,
            "outcome": "released", "policy_hash": DIGEST, "request": CANARY, "headers": {"Authorization": CANARY},
            "body": CANARY, "reason": CANARY, "name": CANARY, "url": "https://example.invalid/" + CANARY})
        batch, cursor = self.read()
        self.assertEqual(cursor.rowid, 1)
        self.assertEqual(len(batch), 1)
        self.assertNotIn(CANARY, json.dumps(batch[0].audit_payload))
        self.assertEqual(batch[0].audit_payload["details"]["credential_ref"], credential)
        self.assertEqual(batch[0].audit_payload["source"]["created_at"], CREATED)
        self.assertEqual(batch[0].audit_payload["review_path"], "/#audit")
        self.assertIsNone(batch[0].action_payload)

    def test_unknown_and_recursive_events_advance(self):
        self.append("notification.delivery.failed", {"error": CANARY})
        self.append("unknown." + CANARY)
        third = self.append("operator_catalog.application.created", {"resource_id": str(uuid.uuid4())})
        batch, cursor = self.read(limit=2)
        self.assertEqual(batch, ())
        self.assertEqual(cursor.rowid, 2)
        next_batch, next_cursor = self.read(cursor)
        self.assertEqual([item.event_id for item in next_batch], [third])
        self.assertEqual(next_cursor.rowid, 3)

    def test_cursor_anchor_and_chain_are_pinned(self):
        self.append()
        _, cursor = self.read()
        self.append()
        with self.assertRaisesRegex(events.NotificationEventError, "^operator notification source unavailable$"):
            self.read(events.EventCursor(cursor.rowid, str(uuid.uuid4()), cursor.event_hash))
        self.writer.execute("UPDATE audit_events SET prev_event_hash=? WHERE rowid=2", (DIGEST,))
        self.writer.commit()
        with self.assertRaises(events.NotificationEventError):
            self.read(cursor)

    def test_invalid_nullable_hash_is_not_treated_as_genesis(self):
        self.append()
        self.writer.execute("UPDATE audit_events SET prev_event_hash=?", ("x" * 500,))
        self.writer.commit()
        with self.assertRaises(events.NotificationEventError):
            self.read()

    def test_explicit_head_baseline_does_not_replay_history(self):
        self.append()
        with self.reader() as conn:
            cursor = events.head_cursor(conn)
        new_id = self.append()
        batch, next_cursor = self.read(cursor)
        self.assertEqual([item.event_id for item in batch], [new_id])
        self.assertEqual(next_cursor.rowid, 2)

    def test_committed_only_and_snapshot_stability(self):
        self.append()
        with self.reader() as conn:
            cursor = events.head_cursor(conn)
            self.append(commit=False)
            self.assertEqual(events.read_batch(conn, cursor, now_epoch_ms=NOW_MS), ((), cursor))
            with self.reader() as other:
                self.assertEqual(events.head_cursor(other), cursor)
            self.writer.commit()
            self.assertEqual(events.read_batch(conn, cursor, now_epoch_ms=NOW_MS), ((), cursor))
        batch, new_cursor = self.read(cursor)
        self.assertEqual(len(batch), 1)
        self.assertEqual(new_cursor.rowid, 2)

    def test_rejects_write_or_uncommitted_reader_context(self):
        self.append()
        with self.reader() as conn:
            conn.execute("PRAGMA query_only=OFF")
            with self.assertRaises(events.NotificationEventError):
                events.head_cursor(conn)
        with self.reader() as conn:
            conn.execute("PRAGMA read_uncommitted=ON")
            with self.assertRaises(events.NotificationEventError):
                events.head_cursor(conn)
        self.writer.execute("BEGIN")
        self.writer.execute("PRAGMA query_only=ON")
        with self.assertRaises(events.NotificationEventError):
            events.head_cursor(self.writer)
        self.writer.rollback()
        with self.reader() as conn:
            conn.rollback()
            with self.assertRaises(events.NotificationEventError):
                events.head_cursor(conn)

    def test_bounded_or_invalid_payload_is_metadata_only(self):
        for raw in (json.dumps({"body": CANARY * 1000}), '{"body":1,"body":2}', '{"body":NaN}',
                    '{"body":' + '[' * 30 + '0' + ']' * 30 + '}'):
            self.append(raw=raw)
        batch, cursor = self.read()
        self.assertEqual(cursor.rowid, 4)
        self.assertTrue(all(item.audit_payload["projection"] == "metadata_only" for item in batch))
        self.assertNotIn(CANARY, json.dumps([item.audit_payload for item in batch]))

    def test_legacy_action_is_exact_current_and_secret_safe(self):
        identifier, _ = self.pending()
        batch, _ = self.read()
        action = batch[0].action_payload
        self.assertIsNotNone(action)
        self.assertEqual(action["approval_ref"]["id"], identifier)
        self.assertEqual(action["summary"], "Review approval request")
        self.assertNotIn(CANARY, json.dumps(action))
        with self.reader(forbid_secrets=True) as conn:
            self.assertTrue(events.action_is_current(conn, action, now_epoch_ms=NOW_MS))
            self.assertFalse(events.action_is_current(conn, action, now_epoch_ms=NOW_MS + 60_000))
            changed = dict(action, expires_at=(NOW + timedelta(days=1)).isoformat())
            self.assertFalse(events.action_is_current(conn, changed, now_epoch_ms=NOW_MS))
        self.writer.execute("UPDATE approval_requests SET status='approved' WHERE id=?", (identifier,))
        self.writer.commit()
        with self.reader() as conn:
            self.assertFalse(events.action_is_current(conn, action, now_epoch_ms=NOW_MS))

    def test_jit_action_does_not_read_encrypted_review(self):
        identifier, _ = self.pending(jit=True)
        with self.reader(forbid_secrets=True) as conn:
            batch, _ = events.read_batch(conn, events.EventCursor(), now_epoch_ms=NOW_MS)
            action = batch[0].action_payload
            self.assertIsNotNone(action)
            self.assertTrue(events.action_is_current(conn, action, now_epoch_ms=NOW_MS))
        self.writer.execute("UPDATE approval_requests SET request_digest=? WHERE id=?", ("sha256:" + "b" * 64, identifier))
        self.writer.commit()
        with self.reader() as conn:
            self.assertFalse(events.action_is_current(conn, action, now_epoch_ms=NOW_MS))

    def test_control_action_binding_and_nullable_field_refusal(self):
        identifier, _ = self.pending(control=True)
        with self.reader(forbid_secrets=True) as conn:
            batch, _ = events.read_batch(conn, events.EventCursor(), now_epoch_ms=NOW_MS)
            action = batch[0].action_payload
            self.assertIsNotNone(action)
            self.assertNotIn(CANARY, json.dumps(action))
            self.assertTrue(events.action_is_current(conn, action, now_epoch_ms=NOW_MS))
        self.writer.execute("UPDATE control_plane_approvals SET resource_id=? WHERE id=?", ("x" * 1000, identifier))
        self.writer.commit()
        with self.reader() as conn:
            self.assertFalse(events.action_is_current(conn, action, now_epoch_ms=NOW_MS))

    def test_unknown_action_schema_and_http_failure_never_imply_key_ready(self):
        _, payload = self.pending(control=True)
        payload["hardware_ready"] = True
        self.append("control_plane.approval.requested", payload)
        self.append("control_plane.mfa.required", {"http_status": 412, "challenge": CANARY})
        batch, cursor = self.read()
        self.assertEqual(cursor.rowid, 3)
        self.assertIsNotNone(batch[0].action_payload)
        self.assertIsNone(batch[1].action_payload)
        self.assertEqual(len(batch), 2)
        self.assertNotIn("security key", json.dumps([item.audit_payload for item in batch]))

    def test_missing_approval_owner_suppresses_action_not_audit(self):
        self.pending(control=True)
        self.writer.execute("DROP TABLE control_plane_approvals")
        self.writer.commit()
        batch, _ = self.read()
        self.assertEqual(len(batch), 1)
        self.assertIsNone(batch[0].action_payload)

    def test_audit_payload_revalidation_is_exact_and_type_sensitive(self):
        self.append(payload={"credential_ref": str(uuid.uuid4()), "credential_version": 1,
            "method": "GET", "upstream_status": 200, "body": CANARY})
        batch, _ = self.read()
        audit = batch[0].audit_payload
        with self.reader(forbid_secrets=True) as conn:
            self.assertTrue(events.payload_matches_source(conn, audit, now_epoch_ms=NOW_MS))
            for key, value in (("request", {"Authorization": CANARY}), ("credential_version", True),
                               ("upstream_status", 200.0)):
                changed = json.loads(json.dumps(audit))
                changed["details"][key] = value
                self.assertFalse(events.payload_matches_source(conn, changed, now_epoch_ms=NOW_MS))
            for key, value in (("event_hash", DIGEST), ("event_type", "notification.test"),
                               ("created_at", EXPIRES), ("event_id", str(uuid.uuid4()))):
                changed = json.loads(json.dumps(audit))
                changed["source"][key] = value
                self.assertFalse(events.payload_matches_source(conn, changed, now_epoch_ms=NOW_MS))
            self.assertFalse(events.payload_matches_source(conn, dict(audit, summary=CANARY), now_epoch_ms=NOW_MS))
            self.assertFalse(events.payload_matches_source(conn, dict(audit, delivery_id=str(uuid.uuid4())), now_epoch_ms=NOW_MS))

    def test_historical_audit_matches_without_current_approval_owner(self):
        self.pending(control=True)
        batch, _ = self.read()
        audit, action = batch[0].audit_payload, batch[0].action_payload
        self.writer.execute("DROP TABLE control_plane_approvals")
        self.writer.commit()
        with self.reader(forbid_secrets=True) as conn:
            self.assertTrue(events.payload_matches_source(conn, audit, now_epoch_ms=NOW_MS + 120_000))
            self.assertFalse(events.action_is_current(conn, action, now_epoch_ms=NOW_MS + 120_000))
            self.assertFalse(events.payload_matches_source(conn, action, now_epoch_ms=NOW_MS))

    def test_metadata_only_audit_revalidation_stays_safe(self):
        identifier = self.append(raw=json.dumps({"body": CANARY * 1000}))
        batch, _ = self.read()
        audit = batch[0].audit_payload
        self.assertEqual(audit["projection"], "metadata_only")
        with self.reader(forbid_secrets=True) as conn:
            self.assertTrue(events.payload_matches_source(conn, audit, now_epoch_ms=NOW_MS))
            changed = dict(audit, details={"body": CANARY})
            self.assertFalse(events.payload_matches_source(conn, changed, now_epoch_ms=NOW_MS))
        self.writer.execute("DELETE FROM audit_events WHERE id=?", (identifier,))
        self.writer.commit()
        with self.reader() as conn:
            self.assertFalse(events.payload_matches_source(conn, audit, now_epoch_ms=NOW_MS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
