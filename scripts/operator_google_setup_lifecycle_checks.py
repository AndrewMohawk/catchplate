"""Real SQLite/ASGI setup lifecycle controls; called by the isolated test worker.

The parent supplies an already-seeded Fixture and a fail-on-provider-contact
sentinel. These checks are not a deployment or provider integration test.
"""
from contextlib import closing
import json
import sqlite3
import uuid


PATH = "/api/operator-demo/oauth/google/setup"
TABLE = "operator_google_setups"


def _record(f, identifier):
    with closing(f.db.connect()) as conn:
        row = conn.execute("SELECT * FROM " + TABLE + " WHERE operation_id=?", (identifier,)).fetchone()
        assert row is not None
        return dict(row)


def _http_refused(f, path, body):
    before = f.snapshot()
    f.call("POST", path, body=body, expected=409)
    assert f.snapshot() == before


def _sql_refused(f, sql, parameters):
    before = f.snapshot()
    with closing(f.db.connect()) as conn:
        conn.execute("PRAGMA recursive_triggers=OFF")
        assert conn.execute("PRAGMA recursive_triggers").fetchone()[0] == 0
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(sql, parameters)
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("retained setup SQL mutation was accepted")
        finally:
            conn.rollback()
    assert f.snapshot() == before


def run_lifecycle_checks(f):
    first = f.prepare()
    first_id = first["operation_id"]
    original = _record(f, first_id)
    binding = json.loads(original["binding_json"])
    actor = binding["actor_id"]
    pending_review = f.setup_review()
    assert pending_review["eligible"] is False
    competing = {key: pending_review[key] for key in (
        "expected_revision", "expected_policy_hash", "expected_settings_digest")}
    competing.update(operation_id=str(uuid.uuid4()), client_id=first["client_id"])
    _http_refused(f, PATH, competing)  # Fresh CAS cannot silently supersede pending work.

    stale_cancel = {**f.review(), "operation_id": first_id}
    with closing(f.db.connect()) as conn:
        catalog = f.schema.read_catalog(conn)
    active_rules = [row for row in catalog["access_rules"] if row["status"] == "active"]
    assert len(active_rules) == 1
    f.mutations.revoke_application(f.inputs.TargetInput(
        **f.review(), id=active_rules[0]["application_id"]), actor)
    current = f.review()
    assert current["expected_policy_hash"] != first["policy_hash"]
    assert current["expected_revision"] == stale_cancel["expected_revision"] + 1
    assert _record(f, first_id) == original
    _http_refused(f, PATH + "/cancel", stale_cancel)

    authority = f.authority()
    settings = f.rows("operator_demo_settings")
    cancelled = f.call("POST", PATH + "/cancel", body={**current, "operation_id": first_id})
    assert cancelled["status"] == "cancelled" and cancelled["activation_receipt"] is None
    assert cancelled["revision"] == current["expected_revision"] + 1
    assert cancelled["policy_hash"] == first["policy_hash"]  # Immutable original review.
    assert f.public(first_id) == cancelled
    assert f.authority() == authority and f.rows("operator_demo_settings") == settings
    retained = _record(f, first_id)
    assert retained["binding_json"] == original["binding_json"]
    assert retained["actor_id"] == actor
    assert retained["terminal_revision"] == cancelled["revision"]
    assert retained["terminal_policy_hash"] == current["expected_policy_hash"]
    with closing(f.db.connect()) as conn:
        event = conn.execute("SELECT * FROM audit_events WHERE id=?",
            ("operator-google-setup:" + first_id + ":cancelled",)).fetchone()
        assert event is not None and event["event_type"] == "operator_catalog.google_setup.cancelled"
        assert event["actor_type"] == "admin" and event["actor_id"] == actor
        assert json.loads(event["event_json"]) == {
            "operation_id": first_id, "actor_id": actor, "status": "cancelled",
            "revision": cancelled["revision"], "policy_hash": current["expected_policy_hash"],
            "profile_binding_digest": binding["profile_binding_digest"],
            "completed_at": cancelled["completed_at"]}

    reused = f.payload()
    reused["operation_id"] = first_id
    _http_refused(f, PATH, reused)  # Current CAS cannot make a retained UUID reusable.
    _http_refused(f, PATH + "/cancel", {**f.review(), "operation_id": first_id})
    second = f.prepare()
    second_id = second["operation_id"]
    assert second_id != first_id and second["policy_hash"] == current["expected_policy_hash"]
    assert second["reviewed_revision"] == cancelled["revision"]
    assert _record(f, first_id) == retained and f.public(first_id) == cancelled
    pending = _record(f, second_id)

    columns = ("operation_id", "actor_id", "status", "binding_json", "terminal_revision",
        "terminal_policy_hash", "completed_at")
    insert = "INSERT OR REPLACE INTO " + TABLE + " (" + ",".join(columns) + ") VALUES (?,?,?,?,?,?,?)"
    _sql_refused(f, insert, tuple(retained[key] for key in columns))
    _sql_refused(f, insert, tuple(pending[key] for key in columns))
    replacement = dict(pending)
    replacement["operation_id"] = str(uuid.uuid4())
    replacement_binding = json.loads(replacement["binding_json"])
    replacement_binding["operation_id"] = replacement["operation_id"]
    replacement["binding_json"] = json.dumps(replacement_binding, sort_keys=True,
        separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    _sql_refused(f, insert, tuple(replacement[key] for key in columns))
    _sql_refused(f, "UPDATE OR REPLACE " + TABLE + " SET status='pending',terminal_revision=NULL,"
        "terminal_policy_hash=NULL,completed_at=NULL WHERE operation_id=?", (first_id,))
    _sql_refused(f, "DELETE FROM " + TABLE + " WHERE operation_id=?", (first_id,))
    assert _record(f, first_id) == retained and _record(f, second_id) == pending
    assert f.public(first_id) == cancelled and f.public(second_id) == second
    assert f.setup_review()["eligible"] is False
    f.disabled()
    return {"cancelled": 1, "reprepared": 1, "http_conflicts": 4,
        "sql_retention_refusals": 5, "provider_contacts": len(f.provider_calls)}
