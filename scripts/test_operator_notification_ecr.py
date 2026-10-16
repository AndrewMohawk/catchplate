#!/usr/bin/env python3
"""ECR notification projections and real local outbox; never receiver delivery.

The pending-owner DTO is an explicit fixture double. Owner source joins have
their own tests; this suite checks the notification boundary, closed audit
projections, exact rechecks, encrypted receiver slots and durable deduplication.
"""
from contextlib import closing
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

import test_operator_notification_events as source_tests

events = source_tests.events
ecr = events.ecr
DIGEST = source_tests.DIGEST
NOW = source_tests.NOW_MS
ROOT = Path(__file__).resolve().parents[1]
CANARY = source_tests.CANARY


def publication():
    return {"assurance": "host-trusted", "publication_id": str(uuid.uuid4()),
        "principal_id": "agent:fixture", "route_id": "operator.fixture",
        "credential_id": str(uuid.uuid4()), "credential_generation": 1,
        "policy_hash": DIGEST, "manifest_digest": DIGEST, "artifact_sha256": DIGEST}


def pending(event, now=NOW, reviewer="user:admin"):
    return {key: event[key] for key in ecr.COMMON - {"assurance"}} | {
        "created_at_epoch_ms": now - 10000, "expires_at_epoch_ms": now + 60000,
        "reviewer_id": reviewer}


def lifecycle(event):
    child = {"child_id": str(uuid.uuid4()), "action": "PutImage", "request_sha256": DIGEST}
    for kind in ecr.SUMMARIES:
        suffix = kind.removeprefix(ecr.PREFIX)
        extra = {}
        admin = suffix in {"reviewed", "approved", "denied", "artifacts_retirement_requested", "artifacts_retired"}
        if suffix == "reviewed":
            extra = {"review_receipt_id": str(uuid.uuid4()), "review_digest": DIGEST}
        elif suffix in {"approved", "denied"}:
            extra = {"review_digest": DIGEST}
        elif suffix in {"reserved", "possible_send", "acknowledged"}:
            extra = dict(child)
            if suffix == "acknowledged":
                extra.update(response_sha256=DIGEST, resulting_status="published", authority_changed=False)
        elif suffix == "recovered":
            extra = {"resulting_status": "uncertain"}
        elif suffix in {"expired", "failed", "uncertain"}:
            extra = dict(child, reason=CANARY)
        elif suffix == "artifacts_retired":
            extra = {"removed_files_this_attempt": 3, "removed_bytes_this_attempt": 32}
        yield kind, event | extra, "admin" if admin else "proxy", "user:admin" if admin else event["principal_id"]


class ProjectionTests(unittest.TestCase):
    setUp = source_tests.EventTests.setUp
    tearDown = source_tests.EventTests.tearDown
    reader = source_tests.EventTests.reader
    append = source_tests.EventTests.append
    read = source_tests.EventTests.read

    def staged(self):
        event = publication()
        self.append(ecr.STAGED, event, actor_type="proxy", actor=event["principal_id"])
        return event

    def owner(self, dto):
        fake = SimpleNamespace(notification_pending=lambda *args, **kwargs: deepcopy(dto))
        # Import lazily inside ecr.action, without importing configured owners.
        import serverware
        return patch.object(serverware, "operator_ecr_publications", fake, create=True)

    def test_all_fifteen_audit_types_are_closed_and_only_staged_is_actionable(self):
        event = publication()
        for kind, value, actor_type, actor in lifecycle(event):
            self.append(kind, value, actor_type=actor_type, actor=actor)
            self.assertIn(kind, events.AUDIT_EVENT_TYPES)
            self.assertEqual(kind in events.ACTION_EVENT_TYPES, kind == ecr.STAGED)
        with self.owner(pending(event)), self.reader(forbid_secrets=True) as conn:
            batch, cursor = events.read_batch(conn, events.EventCursor(), now_epoch_ms=NOW)
            self.assertEqual(len(batch), 15)
            self.assertEqual(cursor.rowid, 15)
            self.assertEqual(sum(item.action_payload is not None for item in batch), 1)
            for item in batch:
                self.assertTrue(events.payload_matches_source(conn, item.audit_payload, now_epoch_ms=NOW))
                self.assertNotIn(CANARY, json.dumps(item.audit_payload))
                self.assertNotIn("review_receipt_id", item.audit_payload["details"])
            uncertain = next(item for item in batch if item.event_type.endswith(".uncertain"))
            self.assertIn("do not retry", uncertain.audit_payload["summary"])
            retired = next(item for item in batch if item.event_type.endswith(".artifacts_retired"))
            self.assertEqual(retired.audit_payload["details"]["removed_files_this_attempt"], 3)
            self.assertIn("AWS images and audit history retained", retired.audit_payload["summary"])
            self.assertEqual(conn.total_changes, 0)

    def test_staged_exact_owner_pins_reviewer_and_original_expiry(self):
        event = self.staged()
        dto = pending(event)
        with self.owner(dto):
            batch, _ = self.read()
            action = batch[0].action_payload
            self.assertTrue(ecr.action_payload(action))
            self.assertEqual(action["review_path"], "/#pending-actions")
            self.assertEqual(action["approval_ref"]["id"], event["publication_id"])
            with self.reader(forbid_secrets=True) as conn:
                self.assertTrue(ecr.matches_source(conn, action, reviewer_id="user:admin", now_epoch_ms=NOW))
                self.assertFalse(ecr.matches_source(conn, action, reviewer_id="other-admin", now_epoch_ms=NOW))
                self.assertFalse(ecr.matches_source(conn, action, reviewer_id="user:admin", now_epoch_ms=NOW + 60000))
        for key, changed in (("publication_id", str(uuid.uuid4())), ("credential_generation", 2),
                ("policy_hash", "sha256:" + "b" * 64), ("manifest_digest", "sha256:" + "b" * 64),
                ("artifact_sha256", "sha256:" + "b" * 64), ("route_id", "operator.changed"),
                ("principal_id", "agent:changed"), ("credential_id", str(uuid.uuid4())),
                ("reviewer_id", "other-admin"), ("expires_at_epoch_ms", NOW + 120000)):
            with self.subTest(key=key), self.owner(dto | {key: changed}), self.reader() as conn:
                self.assertFalse(ecr.matches_source(conn, action, reviewer_id="user:admin", now_epoch_ms=NOW))
                self.assertTrue(events.payload_matches_source(conn, batch[0].audit_payload, now_epoch_ms=NOW))
        with self.owner(None), self.reader() as conn:
            self.assertFalse(ecr.matches_source(conn, action, reviewer_id="user:admin", now_epoch_ms=NOW))
            current, _ = events.read_batch(conn, events.EventCursor(), now_epoch_ms=NOW)
            self.assertIsNone(current[0].action_payload)
            self.assertTrue(events.payload_matches_source(conn, batch[0].audit_payload, now_epoch_ms=NOW))

    def test_malformed_source_and_action_tampering_never_create_a_notice(self):
        event = self.staged()
        with self.owner(pending(event)):
            batch, cursor = self.read()
            action = batch[0].action_payload
            for mutate in (lambda item: item.update(review_path="https://evil.example/"),
                    lambda item: item["details"]["ecr_publication"].update(secret=CANARY),
                    lambda item: item["approval_ref"].update(source_digest="sha256:" + "b" * 64),
                    lambda item: item["details"]["ecr_publication"].update(credential_generation=True),
                    lambda item: item.update(expires_at="2099-01-01T00:00:00+00:00")):
                changed = deepcopy(action)
                mutate(changed)
                self.assertFalse(ecr.action_payload(changed))
            for change in ({"secret": CANARY}, {"assurance": "native"}, {"credential_generation": True},
                    {"artifact_sha256": CANARY}, {"principal_id": None}):
                self.append(ecr.STAGED, event | change, actor_type="proxy", actor=event["principal_id"])
            self.append(ecr.STAGED, event, actor_type="admin", actor="user:admin")
            self.append(ecr.PREFIX + "artifacts_retired", event | {
                "removed_files_this_attempt": True, "removed_bytes_this_attempt": 0}, actor_type="admin", actor="user:admin")
            self.assertEqual(self.read(cursor)[0], ())


def outbox():
    import test_operator_notification_store as store_tests
    from serverware import operator_ecr_publications as owner
    f = store_tests.Fixture()
    from serverware import operator_notifications as worker
    now = f.store._now()
    event = publication()
    dto = pending(event, now, f.config.ADMIN_USER_ID)
    current = [dto]
    def observed(conn, publication_id, *, reviewer_id=None, now_epoch_ms):
        assert conn.in_transaction and conn.total_changes == 0
        assert conn.execute("PRAGMA query_only").fetchone()[0] == 1
        assert publication_id == event["publication_id"]
        return deepcopy(current[0])
    def append(kind, value):
        with closing(f.db.connect()) as conn, conn:
            return f.db.append_audit_event(conn, event_type=kind, actor_type="proxy",
                actor_id=event["principal_id"], event=value)
    with patch.object(owner, "readiness", return_value=True), \
            patch.object(owner, "notification_pending", side_effect=observed), \
            patch.object(f.transport, "deliver", side_effect=AssertionError("no receiver calls")), \
            patch.object(f.transport, "_resolve", side_effect=AssertionError("no DNS")):
        for slot in f.store.SLOTS:
            f.save(slot, event_types=[ecr.STAGED] if slot.startswith("action_required") else [ecr.STAGED, ecr.PREFIX + "uncertain"])
        source = append(ecr.STAGED, event)
        result = f.store.consume_events(f.store._now())
        assert result["queued"] == 4 and result["suppressed"] == 0
        assert f.store.consume_events(f.store._now())["queued"] == 0
        with closing(f.db.connect()) as conn:
            assert conn.execute("SELECT COUNT(*) FROM operator_notification_deliveries WHERE source_event_id=?",
                (source["id"],)).fetchone()[0] == 4
        # One action passes both local checks, then an explicitly unknown
        # transport receipt must never be automatically retried.
        claim = f.store.claim_next(f.store._now())
        assert f.store.is_ecr_action(claim) and f.store.current(claim, f.store._now())
        assert worker._before_dispatch(claim)
        outgoing = worker._outbound_payload(claim)
        assert outgoing["review_url"] == "https://console.example.com/#pending-actions"
        f.clean_public(outgoing)
        for adapter in ("slack", "webhook"):
            rendered = f.transport._payload(adapter, outgoing).decode()
            assert "https://console.example.com/#pending-actions" in rendered
            assert CANARY not in rendered
        f.store.finish(claim, f.transport.DeliveryResult("outcome_unknown", "delivery_unknown"), f.store._now())
        # A reviewer decision, expiry or current-authority change removes the
        # owner projection. Its queued action is suppressed, audit remains valid.
        current[0] = None
        seen = []
        while (claim := f.store.claim_next(f.store._now())) is not None:
            if claim.channel == "action_required":
                assert f.store.is_ecr_action(claim) and not f.store.current(claim, f.store._now())
                seen.append("stale_action")
            else:
                assert f.store.current(claim, f.store._now())
                assert worker._outbound_payload(claim)["review_url"] == "https://console.example.com/#audit"
                f.store.finish(claim, f.transport.DeliveryResult("acknowledged", "acknowledged", 200), f.store._now())
                seen.append("audit")
        assert sorted(seen) == ["audit", "audit", "stale_action"]
        child = {"reason": CANARY, "child_id": str(uuid.uuid4()), "action": "PutImage", "request_sha256": DIGEST}
        append(ecr.PREFIX + "uncertain", event | child)
        result = f.store.consume_events(f.store._now())
        assert result["queued"] == 2 and result["suppressed"] == 0
        for _ in range(2):
            claim = f.store.claim_next(f.store._now())
            assert claim.channel == "audit_log" and f.store.current(claim, f.store._now())
            assert "do not retry" in claim.payload["summary"] and CANARY not in json.dumps(claim.payload)
            f.store.finish(claim, f.transport.DeliveryResult("acknowledged", "acknowledged", 200), f.store._now())
        assert f.store.claim_next(f.store._now() + 180000) is None
        queue = f.store.status()["queue"]
        assert queue["outcome_unknown"] == 1 and queue["suppressed"] == 1 and queue["acknowledged"] == 4
        assert f.db.verify_audit_chain()["ok"]
    return {"independent_slots": 4, "deduplication": True, "stale_action_suppressed": True,
        "unknown_no_retry": True, "receiver_delivery": False}


class OutboxTests(unittest.TestCase):
    def setUp(self):
        import test_operator_notification_store as store_tests
        store_tests.configure_environment(self)

    def test_real_saved_slots_cursor_outbox_and_authenticated_review_link(self):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--outbox"],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-55:]))
        value = json.loads(result.stdout)
        self.assertEqual(value["independent_slots"], 4)
        self.assertTrue(value["deduplication"] and value["stale_action_suppressed"] and value["unknown_no_retry"])
        self.assertFalse(value["receiver_delivery"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--outbox"]:
        os.umask(0o077)
        print(json.dumps(outbox(), sort_keys=True))
    else:
        unittest.main()
