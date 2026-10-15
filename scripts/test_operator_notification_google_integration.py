#!/usr/bin/env python3
"""Actual Google producers -> committed SQLite -> redacted audit projection.

Run only in the bounded network-none backend harness. Existing cold fixtures
perform actual consent, refresh, reauthorization and disconnect transitions;
only their provider HTTP transport is synthetic. No successful ownership guard
is mocked, no notification delivery occurs, and this is not live Google proof.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_operator_google_consent as consent
import test_operator_google_cleanup as cleanup
import test_operator_google_disconnect as disconnect
import test_operator_google_reauthorization as reauthorization
import test_operator_google_refresh_rejection as rejection
import test_operator_notification_google_events as vectors


def no_network(event, _args):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"}:
        raise AssertionError("Google audit test attempted network access")


def prove(fixture, expected):
    from serverware import operator_notification_events as events
    observed, cursor = [], events.EventCursor()
    with closing(fixture.db.connect()) as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        for _ in range(8):
            batch, following = events.read_batch(conn, cursor, limit=64, now_epoch_ms=time.time_ns() // 1000000)
            observed.extend(batch)
            if following == cursor:
                break
            cursor = following
        else:
            raise AssertionError("Google audit test exceeded its source bound")
        raw = {row["id"]: row for row in conn.execute("SELECT id,event_type,actor_type,event_json FROM audit_events")}
        chosen = [item for item in observed if item.event_type in vectors.KINDS]
        assert set(expected) <= {item.event_type for item in chosen}, "actual producer type was not projected"
        # Every selected-type source row must survive projection; counting only
        # a synthetic expected set could hide a malformed real producer join.
        assert {item.event_id for item in chosen} == {key for key, row in raw.items() if row["event_type"] in vectors.KINDS}
        for item in chosen:
            source = raw[item.event_id]
            payload = item.audit_payload
            assert item.action_payload is None and payload["channel"] == "audit_log"
            assert payload["projection"] == "approved_fields" and payload["review_path"] == "/#audit"
            assert payload["details"]["provider"] == "google"
            assert set(payload["details"]) <= vectors.SAFE
            body = json.loads(source["event_json"])
            for key in ("intent_id", "credential_id", "operation_id", "work_id", "credential_version",
                        "credential_generation", "revision", "policy_hash"):
                if key in payload["details"]:
                    assert payload["details"][key] == body[key]
            assert events.payload_matches_source(conn, payload, now_epoch_ms=time.time_ns() // 1000000)
            assert not events.action_is_current(conn, payload, now_epoch_ms=time.time_ns() // 1000000)
    encoded = json.dumps([item.audit_payload for item in chosen])
    for secret in (consent.ACCESS, consent.REFRESH, consent.REFRESHED, consent.CODE, consent.ADMIN,
                   consent.google_tests.CLIENT_SECRET, reauthorization.NEW_ACCESS,
                   reauthorization.NEW_REFRESH, reauthorization.LATER_ACCESS,
                   "fixture@example.com", "synthetic-google-subject-", fixture.profile.client_id):
        assert secret not in encoded, "private producer field entered notification"
    assert fixture.db.verify_audit_chain()["ok"]
    return {"types": sorted({item.event_type for item in chosen}), "projected": len(chosen), "audit_only": True}


def consent_and_refresh():
    f = cleanup.Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        assert f.callback(code="", error="access_denied", error_description="synthetic refusal")[0] == 400
        # Short synthetic provider lifetime exercises the existing refresh
        # window; this test does not claim a real-time expiry wait.
        f.token_changes["expires_in"] = 30
        core = f.connect()
        f.refresh_core = core
        refreshed = f.app._credential_for_lease(core["id"])
        assert refreshed["credential_version"] > core["credential_version"]
        f.assert_redacted_cleanup()
    return prove(f, (vectors.KINDS[0], vectors.KINDS[1], vectors.KINDS[2], vectors.KINDS[3]))


def reauthorize():
    f = reauthorization.Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core, rules = f.setup_account()
        before = f.authority()
        f.begin_reauthorization(core, rules)
        assert f.callback()[0] == 200
        current, _ = f.adopted(core, before)
        f.begin_reauthorization(current, rules)
        assert f.callback(error="access_denied", error_description="synthetic refusal")[0] == 409
        assert f.public(f.start_payload["operation_id"])["status"] == "denied"
        f.assert_checks()
    return prove(f, vectors.KINDS[5:8])


def disconnect_and_cleanup():
    f = disconnect.Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core = f.connect()
        _, rule = f.application_and_rule(core)
        pending = f.start(core, [rule])["disconnect"]
        f.fail_revocation = True
        f.due(pending["operation_id"])
        result = f.app._reconcile_oauth_revocations(limit=8)
        assert result["failed"] == 1
        assert f.public(core["id"])["disconnect"]["status"] == "retry"
        f.fail_revocation = False
        f.due(pending["operation_id"])
        result = f.app._reconcile_oauth_revocations(limit=8)
        assert result["accepted"] == 1
        assert f.public(core["id"])["disconnect"]["status"] == "accepted"
        f.assert_redacted_cleanup()
    return prove(f, vectors.KINDS[8:13])


def refresh_rejected():
    f = rejection.Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        # Existing fixture performs a real versioned update with an expired
        # synthetic token; no clock/ownership guard is patched.
        core = f.setup_account()
        f.reply = rejection.reply()
        f.error(core, app_path=True)
        assert len(f.events()) == 1
        f.assert_checks()
    return prove(f, (vectors.KINDS[4], vectors.KINDS[13]))


def all_filters():
    f = cleanup.Fixture()
    from serverware import operator_notification_store as store, operator_notification_events as events
    from serverware import operator_notification_transport as transport, operator_notifications as notifications
    added_events = {"operator_catalog.access_rule.npm_install_created",
        "operator_catalog.credential.github_app_created", "operator_catalog.credential.github_app_key_replaced",
        "operator_catalog.x_oauth.configuration_saved", "operator_catalog.application.renewal_enrolled",
        "operator_catalog.application.renewal_cancelled", "operator_catalog.application.token_renewed",
        "operator.host_approval.approved", "operator.host_approval.claimed", "operator.host_approval.denied",
        "operator.host_approval.expired", "operator.host_approval.requested", "operator.host_approval.reviewed"}
    advertised = list(events.AUDIT_EVENT_TYPES)
    # The advertised roster grew; one destination still selects at most 64.
    assert len(advertised) == 77 and added_events <= set(advertised)
    selected = [kind for kind in advertised if kind not in added_events]
    assert len(selected) == 64
    payload = {"operation_id": str(uuid.uuid4()), "slot": "audit_log.webhook", "expected_revision": 0,
        "label": "Original 64 supported audit events", "enabled": True, "event_types": selected, "max_attempts": 1,
        "url_action": "replace", "url": "https://receiver.example.test/synthetic-private-notification-token"}
    assert len(json.dumps(payload).encode()) < 16384
    model = store.SaveInput(**payload)
    for kind in added_events:
        assert store.SaveInput(**{**payload, "event_types": [kind]}).event_types == [kind]
    try:
        store.SaveInput(**{**payload, "event_types": advertised[:65]})
    except ValueError:
        pass
    else:
        raise AssertionError("65 event filters widened the destination selection cap")
    with patch.object(transport, "deliver", side_effect=AssertionError("settings save attempted delivery")), \
            patch.object(transport, "_resolve", side_effect=AssertionError("settings save attempted DNS")):
        saved = store.save(model, consent.workspace.common._ACTOR)
        assert saved["status"] == "saved" and saved["slot_state"]["event_types"] == selected
        assert store.operation_status(payload["operation_id"], consent.workspace.common._ACTOR) == saved
        public = notifications.status()
    assert public["capabilities"]["audit_log"]["event_types"] == advertised
    slot = next(item for item in public["slots"] if item["slot"] == payload["slot"])
    assert slot["event_types"] == selected and slot["revision"] == 1
    assert all(item["revision"] == 0 for item in public["slots"] if item["slot"] != payload["slot"])
    assert public["capabilities"]["action_required"]["source_available"] is False
    with closing(f.db.connect()) as conn:
        assert conn.execute("SELECT count(*) FROM operator_notification_deliveries").fetchone()[0] == 0
    assert f.db.verify_audit_chain()["ok"]
    return {"filters_saved_and_recovered": len(selected), "delivery_count": 0, "action_source_enabled": False}


OPERATIONS = {"consent-refresh": consent_and_refresh, "reauthorization": reauthorize,
    "disconnect-cleanup": disconnect_and_cleanup, "refresh-rejected": refresh_rejected, "all-filters": all_filters}


class GoogleNotificationIntegrationTests(unittest.TestCase):
    def setUp(self):
        consent.OperatorGoogleConsentTests.setUp(self)
        directory = Path(self.scratch.name) / "notification-custody"
        directory.mkdir(mode=0o700)
        self.environment.update(SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED="1",
            SERVERWARE_OPERATOR_NOTIFICATIONS_CUSTODY_DIR=str(directory))

    def worker(self, name):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        return json.loads(result.stdout)

    def test_actual_consent_and_refresh_producers(self):
        self.assertTrue(self.worker("consent-refresh")["audit_only"])

    def test_actual_reauthorization_success_and_failure_producers(self):
        self.assertTrue(self.worker("reauthorization")["audit_only"])

    def test_actual_disconnect_and_cleanup_producers(self):
        self.assertTrue(self.worker("disconnect-cleanup")["audit_only"])

    def test_actual_rejected_refresh_and_failure_producers(self):
        self.assertTrue(self.worker("refresh-rejected")["audit_only"])

    def test_all_64_filters_roundtrip_without_delivery_or_action_enablement(self):
        self.assertEqual(self.worker("all-filters")["filters_saved_and_recovered"], 64)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(no_network)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
