#!/usr/bin/env python3
"""Connected notification store checks; execute only in root's network-none harness.

Fresh real operator SQLite/publication/profile/custody/audit per worker. No HTTP
server, live webhook, hardware or provider is contacted. Socket/DNS transports
are never called; test outcomes are explicit bounded transport-result inputs.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
ACTOR = workspace.common._ACTOR
SECRET_URL = "https://receiver.example.com/notification/SYNTHETIC_SECRET_URL_CANARY?token=PRIVATE_CANARY"
SLACK_URL = "https://hooks.slack.com/services/SYNTHETIC/STORE_TEST/PRIVATE_SLACK_CANARY"


class Fixture:
    """Environment must be frozen before construction; see configure_environment."""
    def __init__(self):
        self.config, self.db, self.demo, self.bundles, self.catalog, self.inputs, self.mutations = workspace.workspace()
        from serverware import operator_notification_store as store, operator_notification_custody as custody
        from serverware import operator_notification_transport as transport
        self.store, self.custody, self.transport = store, custody, transport
        self.directory = Path(os.environ["SERVERWARE_OPERATOR_NOTIFICATIONS_CUSTODY_DIR"])
        self.key_path = self.directory / custody.FILENAME

    def payload(self, slot="audit_log.webhook", **changes):
        status = self.store.status()
        current = next(item for item in status["slots"] if item["slot"] == slot)
        return {"operation_id": str(uuid.uuid4()), "slot": slot, "expected_revision": current["revision"],
            "label": "Build audit receiver" if slot.startswith("audit_log") else "Operator action alerts",
            "enabled": True, "event_types": ["operator_catalog.application.created"] if slot.startswith("audit_log") else ["approval.requested"],
            "max_attempts": 1, "url_action": "replace", "url": SLACK_URL if slot.endswith("slack") else SECRET_URL} | changes

    def save(self, slot="audit_log.webhook", **changes):
        return self.store.save(self.payload(slot, **changes), ACTOR)

    def test(self, slot="audit_log.webhook"):
        current = next(item for item in self.store.status()["slots"] if item["slot"] == slot)
        return self.store.queue_test({"operation_id": str(uuid.uuid4()), "slot": slot,
            "expected_revision": current["revision"]}, ACTOR)

    def snapshot(self):
        with closing(self.db.connect()) as conn:
            return tuple(conn.iterdump())

    def clean_public(self, value):
        encoded = json.dumps(value)
        for canary in (SECRET_URL, SLACK_URL, "SYNTHETIC_SECRET_URL_CANARY", "PRIVATE_CANARY", "PRIVATE_SLACK_CANARY"):
            assert canary not in encoded


def configure_environment(test):
    """Reusable parent-side fixture setup; does not import configured owners."""
    workspace.common.OperatorDemoPersistenceTests.setUp(test)
    directory = Path(test.scratch.name) / "notification-custody"
    directory.mkdir(mode=0o700)
    test.environment.update(SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED="1",
        SERVERWARE_OPERATOR_NOTIFICATIONS_CUSTODY_DIR=str(directory),
        SERVERWARE_PUBLIC_URL="https://console.example.com")


def settings():
    f = Fixture()
    assert not f.key_path.exists() and not (f.config.DATA_DIR / "master.key").exists()
    original = f.store.status()
    assert original["available"] and len(original["slots"]) == 4
    assert all(item["revision"] == 0 and not item["enabled"] for item in original["slots"])
    assert not f.key_path.exists()
    before = f.snapshot()
    payload = f.payload()
    model = f.store.SaveInput(**payload)
    assert "url" not in model.model_dump() and SECRET_URL not in repr(model)
    with patch.object(f.transport, "deliver", side_effect=AssertionError("Save called transport")), \
            patch.object(f.transport, "_resolve", side_effect=AssertionError("Save resolved DNS")):
        result = f.store.save(model, ACTOR)
        assert result["status"] == "saved" and result["revision"] == 1
        f.clean_public(result)
        assert f.store.operation_status(result["operation_id"], ACTOR) == result
        for slot in f.store.SLOTS:
            if slot != "audit_log.webhook":
                f.save(slot)
    assert f.key_path.exists() and not (f.config.DATA_DIR / "master.key").exists()
    assert f.snapshot() != before
    f.clean_public(f.store.status())
    assert all(item["revision"] == 1 and item["secret_present"] for item in f.store.status()["slots"])
    for value in (SECRET_URL, SLACK_URL, "PRIVATE_CANARY", "PRIVATE_SLACK_CANARY"):
        assert value not in "\n".join(f.snapshot())
    try:
        f.store.operation_status(result["operation_id"], "different-actor")
    except f.store.NotificationNotFound:
        pass
    else:
        raise AssertionError("operation receipt ignored actor")
    retained = f.key_path.read_bytes()
    changed = f.save(url_action="keep", url=None, enabled=False)
    assert changed["revision"] == 2 and f.key_path.read_bytes() == retained
    assert next(item for item in f.store.status()["slots"] if item["slot"] == "action_required.slack")["enabled"]
    assert f.db.verify_audit_chain()["ok"]
    return {"independent_slots": 4, "save_does_not_send_or_resolve": True, "no_master_key": True}


def conflicts():
    f = Fixture()
    payload = f.payload()
    result = f.store.save(payload, ACTOR)
    for candidate, code in ((payload, "notification_operation_conflict"),
            (payload | {"operation_id": str(uuid.uuid4())}, "notification_revision_conflict")):
        before = f.snapshot()
        try:
            f.store.save(candidate, ACTOR)
        except f.store.NotificationConflict as error:
            assert error.code == code
        else:
            raise AssertionError("saved revision or operation reuse admitted")
        assert f.snapshot() == before
    before = f.snapshot()
    for changes in ({"url_action": "keep", "url": ""}, {"url_action": "clear", "url": None, "enabled": True},
            {"event_types": ["arbitrary.event"]}, {"event_types": ["approval.requested", "approval.requested"]},
            {"max_attempts": 4}, {"unexpected": SECRET_URL}):
        try:
            f.store.save(f.payload(**changes), ACTOR)
        except f.store.NotificationUnavailable as error:
            assert str(error) == "operator notifications unavailable" and SECRET_URL not in str(error)
        else:
            raise AssertionError("invalid setting admitted")
        assert f.snapshot() == before
    f.save(url_action="clear", url=None, enabled=False)
    assert not next(item for item in f.store.status()["slots"] if item["slot"] == result["slot"])["secret_present"]
    before = f.snapshot()
    for changes in ({"url": "http://receiver.example.com/PRIVATE_CANARY"},
            {"url_action": "keep", "url": None, "enabled": False}):
        try:
            f.store.save(f.payload(**changes), ACTOR)
        except f.store.NotificationInputError as error:
            assert str(error) == "notification input refused"
        else:
            raise AssertionError("definite input error was not distinguished")
        assert f.snapshot() == before
    return {"strict_inputs_and_cas": True}


def explicit_tests():
    f = Fixture()
    for slot in f.store.SLOTS:
        f.save(slot)
        receipt = f.test(slot)
        assert receipt["status"] == "queued" and receipt["delivery_id"]
    seen = []
    for _ in range(4):
        now = f.store._now()
        claim = f.store.claim_next(now)
        assert claim is not None and f.store.current(claim, now)
        assert "PRIVATE" not in repr(claim) and SECRET_URL not in repr(claim)
        assert claim.payload["test"] is True
        with closing(f.db.connect()) as conn:
            retained = conn.execute("SELECT status,attempts FROM operator_notification_deliveries WHERE delivery_id=?", (claim.delivery_id,)).fetchone()
            assert tuple(retained) == ("sending", 1)
        f.store.finish(claim, f.transport.DeliveryResult("acknowledged", "acknowledged", 200), now)
        seen.append(claim.channel)
    assert seen == ["action_required", "audit_log", "action_required", "audit_log"]
    assert f.store.claim_next(f.store._now()) is None
    assert f.store.status()["queue"]["acknowledged"] == 4
    return {"explicit_saved_revision_tests": 4, "fair_channels": True}


def retries_and_unknown():
    f = Fixture()
    f.save(max_attempts=3)
    receipt = f.test()
    now = f.store._now()
    first = f.store.claim_next(now)
    f.store.finish(first, f.transport.DeliveryResult("failed", "dns_unavailable"), now)
    assert f.store.claim_next(now + 29999) is None
    second = f.store.claim_next(now + 30000)
    assert second.delivery_id == first.delivery_id and second.attempt == 2
    f.store.finish(second, f.transport.DeliveryResult("outcome_unknown", "delivery_unknown"), now + 30000)
    assert f.store.claim_next(now + 999999) is None
    assert f.store.operation_status(receipt["operation_id"], ACTOR)["status"] == "outcome_unknown"
    crashed = f.test()
    claimed_at = f.store._now()
    claim = f.store.claim_next(claimed_at)
    assert claim
    with patch.object(f.store, "_PROCESS", str(uuid.uuid4())):
        assert f.store.claim_next(claimed_at + 1000) is None
        assert f.store.operation_status(crashed["operation_id"], ACTOR)["status"] == "sending"
        assert f.store.claim_next(claimed_at + 60001) is None
    assert f.store.operation_status(crashed["operation_id"], ACTOR)["status"] == "outcome_unknown"
    with closing(f.db.connect()) as conn:
        assert conn.execute("SELECT count(*) FROM operator_notification_attempts WHERE state='outcome_unknown'").fetchone()[0] == 2
    return {"positive_predispatch_retry_only": True, "ambiguous_and_restart_no_resend": True}


def replacement():
    f = Fixture()
    f.save()
    queued = f.test()
    f.save(url=SECRET_URL + "-replacement")
    assert f.store.operation_status(queued["operation_id"], ACTOR)["status"] == "suppressed"
    assert f.store.claim_next(f.store._now()) is None
    receipt = f.test()
    claim = f.store.claim_next(f.store._now())
    f.save(url_action="keep", url=None, enabled=False)
    assert not f.store.current(claim, f.store._now())
    assert f.store.operation_status(receipt["operation_id"], ACTOR)["status"] == "suppressed"
    return {"replacement_never_retargets_history": True, "disable_stops_claim": True}


def missing_key():
    f = Fixture()
    f.save()
    f.test()
    held = f.directory.parent / "held-notification-key.json"
    f.key_path.rename(held)
    before = f.snapshot()
    for action in (f.store.status, lambda: f.store.claim_next(f.store._now()), lambda: f.store.save({
            "operation_id": str(uuid.uuid4()), "slot": "audit_log.webhook", "expected_revision": 1,
            "label": "Must not recover", "enabled": True, "event_types": [], "max_attempts": 1,
            "url_action": "replace", "url": SECRET_URL}, ACTOR)):
        try:
            action()
        except f.store.NotificationUnavailable:
            pass
        else:
            raise AssertionError("retained missing key accepted")
        assert not f.key_path.exists() and f.snapshot() == before
    assert held.is_file()
    return {"retained_missing_key_never_recreated": True}


def rollback_orphan():
    f = Fixture()
    payload = f.payload()
    before = f.snapshot()
    with patch.object(f.db, "append_audit_event", side_effect=RuntimeError("synthetic audit failure")):
        try:
            f.store.save(payload, ACTOR)
        except f.store.NotificationUnavailable:
            pass
        else:
            raise AssertionError("failed audit did not rollback")
    assert f.snapshot() == before and f.key_path.exists()
    key_bytes = f.key_path.read_bytes()
    assert f.store.status()["cursor"] is None
    f.store.save(payload, ACTOR)
    assert f.key_path.read_bytes() == key_bytes
    assert f.db.verify_audit_chain()["ok"]
    return {"audit_rollback_atomic": True, "explicit_first_save_recovers_valid_orphan": True}


def committed_events():
    f = Fixture()
    # Historical event is intentionally excluded by the explicit Save baseline.
    workspace.create_application(f.db, f.demo, f.catalog, f.inputs, f.mutations, name="Before notification setup")
    f.save()
    assert f.store.consume_events(f.store._now())["queued"] == 0
    current = workspace.create_application(f.db, f.demo, f.catalog, f.inputs, f.mutations, name="After notification setup")
    result = f.store.consume_events(f.store._now())
    assert result["queued"] == 1
    assert f.store.consume_events(f.store._now())["queued"] == 0
    claim = f.store.claim_next(f.store._now())
    assert claim and claim.payload["source"]["event_type"] == "operator_catalog.application.created"
    assert not claim.payload.get("test") and f.store.current(claim, f.store._now())
    f.store.finish(claim, f.transport.DeliveryResult("acknowledged", "acknowledged", 200), f.store._now())
    assert f.store.consume_events(f.store._now())["queued"] == 0
    assert f.store.status()["queue"]["acknowledged"] == 1
    f.clean_public(f.store.status())
    return {"committed_only_no_history_baseline": True, "retained_cursor_dedup": True}


def retained_grammar():
    f = Fixture()
    saved = f.save()
    with closing(f.db.connect()) as conn, conn:
        original = conn.execute("SELECT slot_json FROM operator_notification_operations WHERE operation_id=?", (saved["operation_id"],)).fetchone()[0]
        conn.execute("UPDATE operator_notification_operations SET slot_json=? WHERE operation_id=?", ('{"url":"' + SECRET_URL + '"}', saved["operation_id"]))
    try:
        f.store.operation_status(saved["operation_id"], ACTOR)
    except f.store.NotificationUnavailable as error:
        assert SECRET_URL not in str(error)
    else:
        raise AssertionError("raw retained receipt fields became public")
    with closing(f.db.connect()) as conn, conn:
        conn.execute("UPDATE operator_notification_operations SET slot_json=? WHERE operation_id=?", (original, saved["operation_id"]))
    test = f.test()
    with closing(f.db.connect()) as conn, conn:
        raw = conn.execute("SELECT payload_json FROM operator_notification_deliveries WHERE delivery_id=?", (test["delivery_id"],)).fetchone()[0]
        payload = json.loads(raw)
        payload["details"] = {"request": SECRET_URL}
        conn.execute("UPDATE operator_notification_deliveries SET payload_json=? WHERE delivery_id=?", (f.store._canonical(payload), test["delivery_id"]))
    claim = f.store.claim_next(f.store._now())
    try:
        f.store.current(claim, f.store._now())
    except f.store.NotificationUnavailable:
        pass
    else:
        raise AssertionError("arbitrary synthetic-test details admitted for dispatch")
    try:
        f.store.operation_status(test["operation_id"], ACTOR)
    except f.store.NotificationUnavailable:
        pass
    else:
        raise AssertionError("malformed synthetic receipt became public")
    return {"closed_public_receipts": True, "exact_test_payload_before_dispatch": True}


def action_source_gate():
    f = Fixture()
    assert f.store.ACTION_SOURCE_AVAILABLE is False
    f.save("action_required.webhook")
    # Inject only an internal queue fixture, not a real ceremony/source proof.
    # The source capability must stop even a previously retained queued action
    # before decrypting its URL or reaching the transport worker.
    now = f.store._now()
    notice = {"schema": "serverware.operatorNotification/v1", "channel": "action_required",
        "source": {"event_id": str(uuid.uuid4()), "event_hash": "sha256:" + "a" * 64,
            "event_type": "approval.requested", "created_at": f.store._iso(now)},
        "summary": "Approval requested", "review_path": "/#audit", "details": {}}
    with f.store._write() as conn:
        identifier = f.store._enqueue(conn, "action_required.webhook", 1, notice["source"]["event_id"], notice, now)
    with patch.object(f.custody, "unseal", side_effect=AssertionError("unsupported action decrypted destination")):
        assert f.store.claim_next(now) is None
    with closing(f.db.connect()) as conn:
        retained = conn.execute("SELECT status,last_code,attempts FROM operator_notification_deliveries WHERE delivery_id=?", (identifier,)).fetchone()
        assert tuple(retained) == ("suppressed", "action_source_unavailable", 0)
    test = f.test("action_required.webhook")
    claim = f.store.claim_next(f.store._now())
    assert claim and f.store.current(claim, f.store._now()) and claim.payload["test"] is True
    return {"real_action_source_explicitly_gated": True, "synthetic_action_test_available": True}


def native_notice(f, phase="prepare_available", *, expires_nanos=None):
    from test_operator_notification_events import native_record
    from serverware.operator_notification_pilot_source import NativePilotNotice
    record = native_record(phase, expires_nanos=expires_nanos if expires_nanos is not None else
        f.store._now() * 1_000_000 + 60_000_000_000)
    return NativePilotNotice(record["selection_sha256"], f.store._canonical(record["observation"]))


def native_ingestion():
    f = Fixture()
    f.save("action_required.webhook", event_types=["native_pilot.security_key_available"])
    f.save("audit_log.webhook", event_types=["native_pilot.prepare_available", "native_pilot.security_key_available"])
    prepare = native_notice(f)
    first = f.store.record_native_observation(prepare, f.store._now())
    assert first["recorded"] is True
    original = f.snapshot()
    duplicate = f.store.record_native_observation(prepare, f.store._now())
    assert duplicate == {"recorded": False, "event_id": first["event_id"]} and f.snapshot() == original
    assert f.store.consume_events(f.store._now())["queued"] == 1  # Audit only: action filter excludes Prepare.
    security = native_notice(f, "security_key_available")
    second = f.store.record_native_observation(security, f.store._now())
    assert second["recorded"] and second["event_id"] != first["event_id"]
    assert f.store.consume_events(f.store._now())["queued"] == 2
    assert f.store.consume_events(f.store._now())["queued"] == 0
    claim = f.store.claim_next(f.store._now())
    assert claim and f.store.is_native_action(claim) and f.store.current(claim, f.store._now())
    assert claim.payload["details"]["native_pilot"]["observation"]["phase"] == "security_key_available"
    assert f.store.ACTION_SOURCE_AVAILABLE is False
    # Local validity is not relay liveness. The worker's changed-source result
    # terminalizes this same claim, and a transport cancellation cannot reopen it.
    assert f.store.suppress_native_claim(claim, f.store._now()) is False
    receipt = f.store.finish(claim, f.transport.DeliveryResult("failed", "dispatch_cancelled"), f.store._now())
    assert receipt["status"] == "suppressed" and receipt["code"] == "native_source_unavailable"
    historical = 0
    while (audit := f.store.claim_next(f.store._now())) is not None:
        assert audit.channel == "audit_log" and not f.store.is_native_action(audit)
        assert f.store.current(audit, f.store._now() + 120000)  # Historical audit is not a current action.
        f.store.finish(audit, f.transport.DeliveryResult("acknowledged", "acknowledged", 200), f.store._now())
        historical += 1
    assert historical == 2 and f.db.verify_audit_chain()["ok"]
    with closing(f.db.connect()) as conn:
        assert conn.execute("SELECT count(*) FROM audit_events WHERE event_type=?", (f.store.events.NATIVE_OBSERVATION_TYPE,)).fetchone()[0] == 2
    return {"deduplicated_native_observations": 2, "independent_phase_filters": True,
        "local_native_binding_not_fresh_relay_authority": True}


def native_rollback_and_collision():
    from serverware.operator_notification_pilot_source import notice_record
    f = Fixture()
    f.save(event_types=["native_pilot.prepare_available"])
    notice = native_notice(f)
    before = f.snapshot()
    original_append = f.db.append_audit_event
    def fail_after_insert(*args, **kwargs):
        original_append(*args, **kwargs)
        raise RuntimeError("injected after real native audit append")
    with patch.object(f.db, "append_audit_event", side_effect=fail_after_insert):
        try:
            f.store.record_native_observation(notice, f.store._now())
        except f.store.NotificationUnavailable:
            pass
        else:
            raise AssertionError("failed native append did not abort publication transaction")
    assert f.snapshot() == before
    identifier = f.store.events.native_event_identifier(notice_record(notice))
    with f.store._write() as conn:
        original_append(conn, event_type=f.store.events.NATIVE_OBSERVATION_TYPE, actor_type="system",
            actor_id="native-pilot-observer", event={"wrong_record": "synthetic collision"}, idempotency_key=identifier)
    collided = f.snapshot()
    try:
        f.store.record_native_observation(notice, f.store._now())
    except f.store.NotificationUnavailable:
        pass
    else:
        raise AssertionError("deterministic native ID collision silently adopted another record")
    assert f.snapshot() == collided
    return {"native_audit_append_atomic": True, "exact_collision_refused": True}


def native_expiry_and_final_recheck():
    f = Fixture()
    f.save("action_required.webhook", event_types=["native_pilot.prepare_available"])
    expired = native_notice(f, expires_nanos=f.store._now() * 1_000_000 - 1)
    before = f.snapshot()
    assert f.store.record_native_observation(expired, f.store._now()) is None
    assert f.snapshot() == before
    expiry = f.store._now() * 1_000_000 + 60_000_000_001
    notice = native_notice(f, expires_nanos=expiry)
    assert f.store.record_native_observation(notice, f.store._now())["recorded"]
    assert f.store.consume_events(f.store._now())["queued"] == 1
    claim = f.store.claim_next(f.store._now())
    assert f.store.is_native_action(claim)
    # Exact nanosecond expiry may arrive while a local DB read completes. The
    # fresh wall-clock check after the snapshot must reject, without rounding.
    with patch.object(f.store.time, "time_ns", side_effect=[expiry - 1, expiry]):
        assert not f.store.current(claim, (expiry - 1) // 1_000_000)
    with closing(f.db.connect()) as conn:
        row = conn.execute("SELECT status,last_code,payload_json FROM operator_notification_deliveries WHERE delivery_id=?", (claim.delivery_id,)).fetchone()
        assert row["status"] == "expired" and row["last_code"] == "action_expired"
        assert json.loads(row["payload_json"])["details"]["native_pilot"]["observation"]["sourceExpiresAtUnixNanos"] == str(expiry)
    assert f.store.claim_next(f.store._now() + 120000) is None
    return {"expired_ingestion_refused": True, "original_nanoseconds_rechecked_after_snapshot": True}


def worker(name):
    actions = {"settings": settings, "conflicts": conflicts, "tests": explicit_tests,
        "retries": retries_and_unknown, "replacement": replacement, "missing-key": missing_key,
        "rollback": rollback_orphan, "events": committed_events, "retained": retained_grammar,
        "action-gate": action_source_gate, "native": native_ingestion,
        "native-rollback": native_rollback_and_collision, "native-expiry": native_expiry_and_final_recheck}
    print(json.dumps(actions[name](), sort_keys=True))


class NotificationStoreTests(unittest.TestCase):
    def setUp(self):
        configure_environment(self)

    def run_worker(self, name):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=70)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-60:]))
        self.assertNotIn("PRIVATE_CANARY", result.stdout)
        return json.loads(result.stdout)

    def test_four_slots_atomic_secret_custody_and_no_send(self):
        self.assertEqual(self.run_worker("settings")["independent_slots"], 4)

    def test_strict_inputs_exact_revisions_and_actor_receipts(self):
        self.assertTrue(self.run_worker("conflicts")["strict_inputs_and_cas"])

    def test_explicit_saved_revision_tests_and_fair_channels(self):
        self.assertEqual(self.run_worker("tests")["explicit_saved_revision_tests"], 4)

    def test_positive_predispatch_only_retry_and_ambiguous_restart(self):
        self.assertTrue(self.run_worker("retries")["ambiguous_and_restart_no_resend"])

    def test_replacement_and_disable_never_retarget_history(self):
        self.assertTrue(self.run_worker("replacement")["replacement_never_retargets_history"])

    def test_retained_missing_key_never_recreated(self):
        self.assertTrue(self.run_worker("missing-key")["retained_missing_key_never_recreated"])

    def test_first_save_audit_rollback_and_explicit_orphan_recovery(self):
        self.assertTrue(self.run_worker("rollback")["audit_rollback_atomic"])

    def test_committed_source_cursor_and_no_historical_replay(self):
        self.assertTrue(self.run_worker("events")["committed_only_no_history_baseline"])

    def test_retained_receipt_and_test_payload_closed_before_dispatch(self):
        self.assertTrue(self.run_worker("retained")["exact_test_payload_before_dispatch"])

    def test_real_action_source_gated_before_decrypt_but_synthetic_test_usable(self):
        self.assertTrue(self.run_worker("action-gate")["real_action_source_explicitly_gated"])

    def test_native_observation_idempotency_independent_filters_and_historical_audit(self):
        self.assertTrue(self.run_worker("native")["independent_phase_filters"])

    def test_native_audit_transaction_rollback_and_exact_identifier_collision(self):
        self.assertTrue(self.run_worker("native-rollback")["exact_collision_refused"])

    def test_native_expiry_refuses_ingestion_and_rechecks_after_local_snapshot(self):
        self.assertTrue(self.run_worker("native-expiry")["original_nanoseconds_rechecked_after_snapshot"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        worker(sys.argv[2])
    else:
        unittest.main()
