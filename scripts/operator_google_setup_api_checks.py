"""Focused real-ASGI/SQLite checks used by the cold Google setup test worker.

The caller supplies a seeded Fixture under its fail-on-provider-contact guard.
These helpers do not start workers, replace successful guards, or enable Google.
Faults are an actual SQLite audit trigger and a committed-but-lost acknowledgement.
"""
from __future__ import annotations

from contextlib import closing
import json
import sqlite3
from unittest.mock import patch
import uuid

PATH = "/api/operator-demo/oauth/google/setup"
EVENT = "operator_catalog.google_setup.prepared"


def _refused(f, method, path, expected, **options):
    before, contacts = f.snapshot(), list(f.provider_calls)
    code, raw, headers = f.request(method, path, **options)
    assert code == expected, (code, expected)
    assert [value for name, value in headers if name.lower() == b"cache-control"] == [b"no-store"]
    assert isinstance(json.loads(raw), dict)
    assert f.snapshot() == before, "refused setup request changed retained state"
    assert f.provider_calls == contacts == [], "setup request contacted a provider"


def _cancel_body(f, identifier):
    return {**f.review(), "operation_id": identifier}


def run_api_checks(f):
    payload = f.payload()
    # Auth/Origin, exact CAS, strict bounded JSON and fixed public client input.
    failures = [
        (payload, {"auth": False}, 401),
        (payload, {"origin": False}, 403),
        (payload, {"headers": (("Origin", "https://different.example.com"),)}, 403),
        ({**payload, "expected_revision": payload["expected_revision"] - 1}, {}, 409),
        ({**payload, "expected_policy_hash": "sha256:" + "0" * 64}, {}, 409),
        ({**payload, "expected_settings_digest": "sha256:" + "0" * 64}, {}, 409),
        ({**payload, "expected_revision": True}, {}, 422),
        ({**payload, "operation_id": "10000000-0000-4000-8000-00000000000A"}, {}, 422),
        ({**payload, "client_id": "https://unreviewed.example.com/client"}, {}, 422),
        ({**payload, "client_id": 123}, {}, 422),
        ({**payload, "client_secret": "synthetic-client-secret-not-a-setup-input"}, {}, 422),
        ({**payload, "scopes": ["openid", "extra"]}, {}, 422),
        (b'{"client_id":"first","client_id":"second"}', {}, 422),
        (b"[]", {}, 422),
        (b" " * 4097, {}, 413),
        (payload, {"headers": (("Content-Encoding", "identity"),)}, 415),
        (payload, {"headers": (("Content-Type", "application/json"),)}, 415),
        (payload, {"headers": (("Content-Length", "0"),)}, 400),
    ]
    for body, options, expected in failures:
        _refused(f, "POST", PATH, expected, body=body, **options)
    missing = str(uuid.uuid4())
    for path, options, expected in (
            (PATH, {"auth": False}, 401),
            (PATH + "?unexpected=1", {}, 422),
            (PATH, {"body": {}}, 400),
            (PATH + "/not-a-uuid", {}, 422),
            (PATH + "/" + missing, {}, 404)):
        _refused(f, "GET", path, expected, **options)
    before = f.snapshot()
    assert f.call("GET", origin=False) == f.setup_review()
    assert f.snapshot() == before

    authority, settings = f.authority(), f.rows("operator_demo_settings")
    raw = json.dumps(payload).encode()
    assert len(raw) < 4096
    operation = f.call("POST", body=raw + b" " * (4096 - len(raw)), expected=201)
    identifier = operation["operation_id"]
    assert identifier == payload["operation_id"] and operation["status"] == "pending"
    assert operation["revision"] == payload["expected_revision"] + 1
    assert operation["activation_receipt"] is None and f.public(identifier) == operation
    assert f.authority() == authority and f.rows("operator_demo_settings") == settings
    assert f.setup_review()["eligible"] is False
    with closing(f.db.connect()) as conn:
        actor = conn.execute("SELECT actor_id FROM operator_google_setups WHERE operation_id=?", (identifier,)).fetchone()[0]
    other_actor = actor + ":other-synthetic-admin"
    before = f.snapshot()
    for action in (
            lambda: f.setup.status(identifier, other_actor),
            lambda: f.setup.cancel(f.setup.CancelInput(**_cancel_body(f, identifier)), other_actor)):
        try:
            action()
        except f.setup.SetupNotFound:
            pass
        else:
            raise AssertionError("another actor observed or cancelled the setup")
        assert f.snapshot() == before
    _refused(f, "GET", PATH + "/" + identifier, 401, auth=False)
    cancel = _cancel_body(f, identifier)
    _refused(f, "POST", PATH + "/cancel", 401, body=cancel, auth=False)
    _refused(f, "POST", PATH + "/cancel", 403, body=cancel, origin=False)
    _refused(f, "POST", PATH + "/cancel", 409, body={**cancel, "expected_revision": cancel["expected_revision"] - 1})
    _refused(f, "POST", PATH + "/cancel", 422, body={**cancel, "client_id": payload["client_id"]})
    _refused(f, "POST", PATH + "/cancel", 413, body=b" " * 2049)
    current = f.setup_review()
    fresh_pins = {key: current[key] for key in ("expected_revision", "expected_policy_hash", "expected_settings_digest")}
    _refused(f, "POST", PATH, 409, body={**payload, **fresh_pins})
    _refused(f, "POST", PATH, 409, body={**payload, **fresh_pins, "operation_id": str(uuid.uuid4())})
    cancelled = f.call("POST", PATH + "/cancel", body=cancel)
    assert cancelled["status"] == "cancelled" and cancelled["operation_id"] == identifier
    assert cancelled["revision"] == operation["revision"] + 1 and cancelled["activation_receipt"] is None
    assert f.public(identifier) == cancelled and f.authority() == authority
    assert f.rows("operator_demo_settings") == settings
    reuse = {**f.payload(), "operation_id": identifier}
    _refused(f, "POST", PATH, 409, body=reuse)
    _refused(f, "POST", PATH + "/cancel", 409, body=_cancel_body(f, identifier))
    f.disabled()
    return {"api_cas_auth_strict_body": True, "owner_bound_status_cancel": True,
        "single_pending_and_uuid_retention": True, "provider_contacts": 0}


def run_transaction_checks(f):
    payload = f.payload()
    with closing(f.db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER google_setup_test_abort BEFORE INSERT ON audit_events "
            "WHEN NEW.event_type='operator_catalog.google_setup.prepared' "
            "BEGIN SELECT RAISE(ABORT,'synthetic setup audit refusal'); END")
    _refused(f, "POST", PATH, 503, body=payload)
    with closing(f.db.connect()) as conn, conn:
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_google_setups'").fetchone() is None
        conn.execute("DROP TRIGGER google_setup_test_abort")
    # Use a fresh explicit operation after the proven rollback, not a retry
    # following an unknown result. The next fault occurs only AFTER real COMMIT.
    payload = f.payload()
    authority, settings, before_revision = f.authority(), f.rows("operator_demo_settings"), payload["expected_revision"]
    event_id = "operator-google-setup:" + payload["operation_id"] + ":prepared"
    committed, original_connect = [], sqlite3.connect

    class LostAcknowledgement(sqlite3.Connection):
        def commit(self):
            saved = self.in_transaction and self.execute(
                "SELECT id FROM audit_events WHERE id=? AND event_type=?", (event_id, EVENT)).fetchone()
            if saved and not committed:
                super().commit()
                committed.append(saved[0])
                raise OSError("synthetic setup committed acknowledgement lost")
            return super().commit()

    def connection(*args, **kwargs):
        assert "factory" not in kwargs
        return original_connect(*args, factory=LostAcknowledgement, **kwargs)

    with patch.object(sqlite3, "connect", side_effect=connection):
        f.call("POST", body=payload, expected=503)
    assert committed == [event_id]
    observed = f.public(payload["operation_id"])
    assert observed["status"] == "pending" and observed["operation_id"] == payload["operation_id"]
    assert observed["revision"] == observed["staged_revision"] == before_revision + 1
    assert observed["activation_receipt"] is None and observed["client_id"] == payload["client_id"]
    assert observed["policy_hash"] == payload["expected_policy_hash"]
    assert f.authority() == authority and f.rows("operator_demo_settings") == settings
    with closing(f.db.connect()) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE id=?", (event_id,)).fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM operator_google_setups").fetchone()[0] == 1
    before = f.snapshot()
    assert f.public(payload["operation_id"]) == observed and f.snapshot() == before
    # Negative duplicate submission only: it must not repeat or replace work.
    _refused(f, "POST", PATH, 409, body=payload)
    f.disabled()
    return {"audit_failure_full_rollback": True, "lost_commit_ack_recovered_by_get": True,
        "prepare_commits": 1, "provider_contacts": 0}
