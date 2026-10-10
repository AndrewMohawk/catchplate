"""Finite real-ASGI/SQLite checks for the isolated upstream setup worker.

No success guards are substituted. Faults are a real audit trigger and a real
committed transaction whose acknowledgement is deliberately lost.
"""
from contextlib import closing
import json
import sqlite3
from unittest.mock import patch
import uuid

import test_operator_google_setup as google

PATH = "/api/operator-demo/proxy/upstreams"
TABLE = "operator_upstream_setups"
EVENT = "operator_catalog.upstream_setup.prepared"
TARGET = [*google.OLD_ORIGINS, "https://registry.npmjs.org"]


def refused(f, method, path=PATH, *, expected, **options):
    before = f.snapshot()
    f.call(method, path, expected=expected, **options)
    assert f.snapshot() == before and not f.provider_calls


def review_checks(f):
    empty = f.setup_review()
    assert empty["eligible"] and empty["fixed_first_origin"] == google.OLD_ORIGINS[0]
    assert empty["pending_operation_id"] is None and empty["blocked_reason"] is None
    refused(f, "POST", body=f.payload([TARGET[-1], *google.OLD_ORIGINS]), expected=422)
    f.seed()
    review = f.setup_review()
    assert review["fixed_first_origin"] is None
    protected = {item["origin"]: item["reasons"] for item in review["protected_origins"]}
    assert set(protected[google.OLD_ORIGINS[0]]) >= {"active_rule", "retained_policy"}
    assert "fixture" in protected[google.OLD_ORIGINS[1]]
    payload = f.payload()
    # Small, explicit boundary matrix; every refusal preserves the complete DB
    # dump and custody/policy/CA file identities, not just the setup row count.
    cases = [
        ({**payload, "allowed_upstreams": TARGET[1:]}, 422),
        ({**payload, "allowed_upstreams": [TARGET[0], TARGET[-1]]}, 422),
        ({**payload, "allowed_upstreams": google.OLD_ORIGINS[::-1]}, 422),
        ({**payload, "allowed_upstreams": [*TARGET, TARGET[-1]]}, 422),
        ({**payload, "allowed_upstreams": [*google.OLD_ORIGINS, "https://REGISTRY.NPMJS.ORG"]}, 422),
        ({**payload, "allowed_upstreams": [*google.OLD_ORIGINS, "https://127.0.0.1"]}, 422),
        ({**payload, "fixture_cidrs": ["127.0.0.2/32"]}, 422),
        ({**payload, "expected_revision": payload["expected_revision"] - 1}, 409),
        ({**payload, "expected_policy_hash": "sha256:" + "0" * 64}, 409),
        ({**payload, "expected_settings_digest": "sha256:" + "0" * 64}, 409),
    ]
    for body, expected in cases:
        refused(f, "POST", body=body, expected=expected)
    operation = f.prepare()
    assert operation["target_settings"]["allowed_upstreams"] == TARGET
    return {"empty_first_origin_protected": True, "retained_origins_protected": True,
        "negative_controls": len(cases) + 1, "new_canonical_public_origin_prepared": True}


def prepare_rollback(f):
    f.seed()
    payload = f.payload()
    with closing(f.db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER upstream_prepare_abort BEFORE INSERT ON audit_events "
            "WHEN NEW.event_type='operator_catalog.upstream_setup.prepared' "
            "BEGIN SELECT RAISE(ABORT,'synthetic upstream preparation audit refusal'); END")
    refused(f, "POST", body=payload, expected=503)
    with closing(f.db.connect()) as conn:
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (TABLE,)).fetchone() is None
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE event_type=?", (EVENT,)).fetchone()[0] == 0
    return {"prepare_audit_failure_full_rollback": True}


def receipt_checks(f):
    f.seed()
    payload = f.payload()
    authority, settings = f.authority(), f.rows("operator_demo_settings")
    event_id = "operator-upstream-setup:" + payload["operation_id"] + ":prepared"
    committed, original_connect = [], sqlite3.connect

    class LostAcknowledgement(sqlite3.Connection):
        def commit(self):
            saved = self.in_transaction and self.execute(
                "SELECT id FROM audit_events WHERE id=? AND event_type=?", (event_id, EVENT)).fetchone()
            if saved and not committed:
                super().commit()
                committed.append(saved[0])
                raise OSError("synthetic upstream acknowledgement lost after commit")
            return super().commit()

    def connection(*args, **kwargs):
        assert "factory" not in kwargs
        return original_connect(*args, factory=LostAcknowledgement, **kwargs)

    with patch.object(sqlite3, "connect", side_effect=connection):
        f.call("POST", body=payload, expected=503)
    assert committed == [event_id]
    observed = f.public(payload["operation_id"])
    assert observed["status"] == "pending" and observed["operation_id"] == payload["operation_id"]
    assert observed["revision"] == payload["expected_revision"] + 1 and observed["activation_receipt"] is None
    assert f.authority() == authority and f.rows("operator_demo_settings") == settings
    before = f.snapshot()
    assert f.public(payload["operation_id"]) == observed and f.snapshot() == before
    refused(f, "POST", body=payload, expected=409)
    assert f.public(payload["operation_id"]) == observed  # Conflict is not proof of absence.
    record, = f.rows(TABLE)
    other = record["actor_id"] + ":different-synthetic-admin"
    cancel = {**f.review(), "operation_id": payload["operation_id"]}
    for action in (lambda: f.upstream.status(payload["operation_id"], other),
            lambda: f.upstream.cancel(f.upstream.CancelInput(**cancel), other)):
        try:
            action()
        except f.upstream.SetupNotFound:
            pass
        else:
            raise AssertionError("upstream receipt or cancellation escaped actor ownership")
        assert f.snapshot() == before
    other_review = f.upstream.review(other)
    assert other_review["pending_operation_id"] is None and other_review["blocked_reason"] == "pending_operation"
    cancelled = f.call("POST", PATH + "/cancel", body=cancel)
    assert cancelled["status"] == "cancelled" and cancelled["activation_receipt"] is None
    assert cancelled["revision"] == observed["revision"] + 1
    assert f.public(payload["operation_id"]) == cancelled and f.authority() == authority
    assert f.rows("operator_demo_settings") == settings
    retained, = f.rows(TABLE)
    assert retained["binding_json"] == record["binding_json"] and retained["actor_id"] == record["actor_id"]
    refused(f, "POST", body={**f.payload(), "operation_id": payload["operation_id"]}, expected=409)
    with closing(f.db.connect()) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE id=?", (event_id,)).fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM " + TABLE).fetchone()[0] == 1
    return {"lost_commit_ack_recovered_by_get": True, "prepare_commits": 1,
        "owner_bound_get_and_cancel": True, "explicit_cancel_retains_original_binding": True}


def google_pending_checks(f):
    f.seed()
    upstream = f.prepare()
    google_review = f.call("GET", google.PATH)
    google_payload = {key: google_review[key] for key in (
        "expected_revision", "expected_policy_hash", "expected_settings_digest")} | {
            "operation_id": str(uuid.uuid4()), "client_id": google.CLIENT}
    assert google_review["eligible"] is False
    refused(f, "POST", google.PATH, body=google_payload, expected=409)
    f.call("POST", PATH + "/cancel", body={**f.review(), "operation_id": upstream["operation_id"]})
    candidate = f.payload()
    google_review = f.call("GET", google.PATH)
    google_payload.update({key: google_review[key] for key in (
        "expected_revision", "expected_policy_hash", "expected_settings_digest")})
    assert google_review["eligible"] is True
    google_operation = f.call("POST", google.PATH, body=google_payload, expected=201)
    assert google_operation["status"] == "pending"
    blocked = f.setup_review()
    assert blocked["eligible"] is False and blocked["blocked_reason"] == "pending_google_setup"
    candidate.update({key: blocked[key] for key in (
        "expected_revision", "expected_policy_hash", "expected_settings_digest")})
    refused(f, "POST", body=candidate, expected=409)
    return {"mutual_exclusion_both_directions": True}


ACTIONS = {"review_checks": review_checks, "receipt_checks": receipt_checks,
    "prepare_rollback": prepare_rollback, "google_pending_checks": google_pending_checks}
