"""Durable, secret-free explicit-disconnect receipts; no provider transport.

The receipt survives encrypted cleanup-work retirement. Accepted means only
that the provider endpoint accepted revocation, never propagation or permission
to reconnect. This first version deliberately retains the local family fence.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid

TABLE = "operator_google_disconnects"
SOURCE = "operator_google_disconnect_v1"
MAX_OPERATIONS = 1024
_TRIGGER = "operator_google_disconnect_identity_immutable"
_DELETE = "operator_google_disconnect_receipt_retained"
_INSERT = "operator_google_disconnect_insert_guard"
_SQL = """CREATE TABLE operator_google_disconnects (
    operation_id TEXT PRIMARY KEY, credential_id TEXT NOT NULL UNIQUE,
    receipt_json TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','retry','accepted')),
    attempts INTEGER NOT NULL CHECK(attempts>=0), next_attempt_at TEXT,
    provider_accepted_at TEXT, reason TEXT NOT NULL) WITHOUT ROWID"""
_UPDATE_SQL = """CREATE TRIGGER operator_google_disconnect_identity_immutable
    BEFORE UPDATE ON operator_google_disconnects
    WHEN NEW.operation_id IS NOT OLD.operation_id OR NEW.credential_id IS NOT OLD.credential_id
      OR NEW.receipt_json IS NOT OLD.receipt_json OR OLD.status='accepted'
    BEGIN SELECT RAISE(ABORT,'operator disconnect receipt is immutable'); END"""
_DELETE_SQL = """CREATE TRIGGER operator_google_disconnect_receipt_retained
    BEFORE DELETE ON operator_google_disconnects
    BEGIN SELECT RAISE(ABORT,'operator disconnect receipt must be retained'); END"""
_INSERT_SQL = """CREATE TRIGGER operator_google_disconnect_insert_guard
    BEFORE INSERT ON operator_google_disconnects
    WHEN EXISTS (SELECT 1 FROM operator_google_disconnects
      WHERE operation_id=NEW.operation_id OR credential_id=NEW.credential_id)
    BEGIN SELECT RAISE(ABORT,'operator disconnect receipt already exists'); END"""
_RECEIPT_KEYS = {"schema", "operation_id", "credential_id", "actor_id", "requested_at",
    "profile_binding_digest", "oauth_client_id", "provider_subject", "credential_ids",
    "affected_rule_ids", "affected_application_ids", "reviewed_revision", "reviewed_policy_hash",
    "revision", "policy_hash", "policy_sequence", "project_wide_acknowledged"}


class DisconnectUnavailable(RuntimeError):
    """Fixed failure, with no original input, secret or provider exception."""


def _require(value):
    if not value:
        raise DisconnectUnavailable("operator Google disconnect unavailable")


def canonical_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _objects(conn):
    return {row["name"]: dict(row) for row in conn.execute(
        "SELECT name,type,tbl_name,sql FROM sqlite_master WHERE name IN (?,?,?,?) "
        "OR (type='trigger' AND tbl_name=?)", (TABLE, _TRIGGER, _DELETE, _INSERT, TABLE)).fetchall()}


def available(conn):
    from catchplate import operator_catalog_google
    _require(isinstance(conn, sqlite3.Connection))
    profile = operator_catalog_google.validate_profile_binding(conn)
    objects = _objects(conn)
    if not objects:
        _require(conn.execute("SELECT 1 FROM oauth_revocation_work WHERE source=? LIMIT 1", (SOURCE,)).fetchone() is None)
        catalog_exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='operator_catalog_credentials'").fetchone()
        if catalog_exists:
            records = conn.execute("SELECT data_json FROM operator_catalog_credentials LIMIT ?",
                (MAX_OPERATIONS + 1,)).fetchall()
            _require(len(records) <= MAX_OPERATIONS)
            for row in records:
                value = json.loads(row["data_json"], object_pairs_hook=_pairs)
                _require(isinstance(value, dict) and "disconnect_operation_id" not in value)
        return False  # A retained older profile is not silently upgraded.
    _require(profile is not None and set(objects) == {TABLE, _TRIGGER, _DELETE, _INSERT})
    for name, kind, definition in ((TABLE, "table", _SQL),
            (_TRIGGER, "trigger", _UPDATE_SQL), (_DELETE, "trigger", _DELETE_SQL), (_INSERT, "trigger", _INSERT_SQL)):
        row = objects[name]
        _require(row["type"] == kind and row["tbl_name"] == TABLE
            and " ".join(row["sql"].split()) == " ".join(definition.split()))
    return True


def initialize(conn, *, fresh_profile):
    from catchplate.operator_publication import assert_held
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction and type(fresh_profile) is bool)
    assert_held()
    if fresh_profile:
        _require(not _objects(conn))
        for statement in (_SQL, _UPDATE_SQL, _DELETE_SQL, _INSERT_SQL):
            conn.execute(statement)
        _require(available(conn))
    else:
        available(conn)  # Old absence is allowed; lost retained ownership is not.


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result)
        result[key] = value
    return result


def _read(row):
    if row is None:
        return None
    from catchplate import operator_google_cleanup_store as cleanup
    raw = row["receipt_json"]
    _require(isinstance(raw, str) and len(raw.encode()) <= 65536)
    receipt = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: _require(False))
    _require(isinstance(receipt, dict) and set(receipt) == _RECEIPT_KEYS
        and receipt["schema"] == "catchplate.operatorGoogleDisconnectReceipt/v1"
        and receipt["operation_id"] == row["operation_id"] and receipt["credential_id"] == row["credential_id"]
        and canonical_uuid(receipt["operation_id"]) and canonical_uuid(receipt["credential_id"])
        and receipt["project_wide_acknowledged"] is True
        and isinstance(receipt["actor_id"], str) and 0 < len(receipt["actor_id"]) <= 512
        and isinstance(receipt["requested_at"], str) and 0 < len(receipt["requested_at"]) <= 64
        and isinstance(receipt["oauth_client_id"], str) and 0 < len(receipt["oauth_client_id"]) <= 256
        and isinstance(receipt["provider_subject"], str) and 0 < len(receipt["provider_subject"]) <= 256)
    for key in ("profile_binding_digest", "reviewed_policy_hash", "policy_hash"):
        _require(isinstance(receipt[key], str) and cleanup._SHA.fullmatch(receipt[key]))
    for key in ("reviewed_revision", "revision", "policy_sequence"):
        _require(type(receipt[key]) is int and 0 < receipt[key] < 9_007_199_254_740_991)
    _require(receipt["revision"] == receipt["reviewed_revision"] + 1)
    for key in ("credential_ids", "affected_rule_ids", "affected_application_ids"):
        values = receipt[key]
        _require(isinstance(values, list) and len(values) <= MAX_OPERATIONS
            and all(canonical_uuid(value) for value in values) and values == sorted(set(values)))
    _require(receipt["credential_id"] in receipt["credential_ids"]
        and row["status"] in {"pending", "retry", "accepted"}
        and type(row["attempts"]) is int and row["attempts"] >= 0
        and row["reason"] in {"cleanup_pending", "provider_outcome_unconfirmed", "provider_accepted"})
    _require((row["status"] == "accepted") == (row["provider_accepted_at"] is not None))
    for key in ("provider_accepted_at", "next_attempt_at"):
        _require(row[key] is None or isinstance(row[key], str) and 0 < len(row[key]) <= 64)
    return {"receipt": receipt, **{key: row[key] for key in
        ("status", "attempts", "next_attempt_at", "provider_accepted_at", "reason")}}


def get(conn, *, operation_id=None, credential_id=None):
    _require(available(conn) and (operation_id is None) != (credential_id is None))
    key, value = ("operation_id", operation_id) if operation_id is not None else ("credential_id", credential_id)
    _require(canonical_uuid(value))
    return _read(conn.execute("SELECT * FROM " + TABLE + " WHERE " + key + "=?", (value,)).fetchone())


def rows(conn):
    if not available(conn):
        return []
    values = conn.execute("SELECT * FROM " + TABLE + " LIMIT ?", (MAX_OPERATIONS + 1,)).fetchall()
    _require(len(values) <= MAX_OPERATIONS)
    return [_read(row) for row in values]


def require_initial_admission(conn):
    from catchplate.operator_catalog_schema import CatalogConflict
    # Even accepted revocation has unproven propagation. This backend-only
    # slice cannot authorize a new unknown-account consent until finalization.
    if rows(conn):
        raise CatalogConflict()


def require_refresh_admission(conn, metadata):
    from catchplate import db
    from catchplate.operator_catalog_schema import CatalogConflict
    family = db._google_oauth_grant_family(metadata)
    for item in rows(conn):
        receipt = item["receipt"]
        if family is not None and db._google_oauth_grant_families_collide(family,
                (receipt["oauth_client_id"], receipt["provider_subject"])):
            raise CatalogConflict()


def require_quiescent(conn, metadata):
    from catchplate import db, operator_catalog_oauth as consent, operator_google_cleanup_store as cleanup
    from catchplate.operator_catalog_schema import CatalogConflict
    values = conn.execute("SELECT * FROM operator_catalog_oauth_intents LIMIT ?",
        (consent.MAX_RETAINED_INTENTS + 1,)).fetchall()
    _require(len(values) <= consent.MAX_RETAINED_INTENTS)
    now = int(time.time())
    for row in values:
        intent = consent._read(row)
        if intent["status"] == "exchanging" or (intent["status"] in {"prepared", "awaiting_consent"}
                and intent["expires_at_epoch"] > now):
            raise CatalogConflict()
    family = db._google_oauth_grant_family(metadata)
    work = conn.execute("SELECT id FROM oauth_revocation_work WHERE provider_id='google' LIMIT ?",
        (cleanup.MAX_FAMILY_SCAN + 1,)).fetchall()
    _require(len(work) <= cleanup.MAX_FAMILY_SCAN)
    for row in work:
        item = cleanup.get_work(row["id"], conn=conn)
        if item is None or item["identity"] is None:
            raise CatalogConflict()
        other = (item["association"]["oauth_client_id"], item["identity"]["provider_subject"])
        if db._google_oauth_grant_families_collide(family, other):
            raise CatalogConflict()


def insert(conn, receipt):
    from catchplate.operator_publication import assert_held
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction and available(conn))
    assert_held()
    _require(len(rows(conn)) < MAX_OPERATIONS)
    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    _require(len(raw.encode()) <= 65536)
    conn.execute("INSERT INTO " + TABLE + " VALUES (?,?,?,'pending',0,NULL,NULL,'cleanup_pending')",
        (receipt["operation_id"], receipt["credential_id"], raw))
    _read(conn.execute("SELECT * FROM " + TABLE + " WHERE operation_id=?", (receipt["operation_id"],)).fetchone())


def _work_receipt(conn, work):
    """Pure SQLite joins; never call eligibility, provider or loaded-state HTTP."""
    from catchplate import operator_catalog_schema as catalog_schema
    item = get(conn, operation_id=work["work_id"])
    _require(item is not None and work["source"] == SOURCE and work["status"] == "pending"
        and work["fence"] is not None and work["identity"] is not None)
    receipt, association, fence = item["receipt"], work["association"], work["fence"]
    _require(association["operation"] == "disconnect"
        and receipt["operation_id"] == association["work_id"] == fence["work_id"]
        and receipt["credential_id"] == association["credential_id"]
        and receipt["actor_id"] == association["actor_id"]
        and receipt["profile_binding_digest"] == association["profile_binding_digest"] == fence["profile_binding_digest"]
        and receipt["oauth_client_id"] == association["oauth_client_id"] == fence["oauth_client_id"]
        and receipt["provider_subject"] == work["identity"]["provider_subject"] == fence["provider_subject"]
        and receipt["credential_ids"] == fence["credential_ids"]
        and receipt["policy_hash"] == fence["policy_hash"] and receipt["revision"] == fence["catalog_revision"])
    core = conn.execute("SELECT attempts FROM oauth_revocation_work WHERE id=?", (work["work_id"],)).fetchone()
    _require(core is not None and core["attempts"] == item["attempts"])
    catalog = catalog_schema.read_catalog(conn)
    catalog_schema.validate_bindings(conn, catalog)
    _require(catalog["revision"] >= receipt["revision"])
    credentials = {row["id"]: row for row in catalog["credentials"]}
    for identifier in receipt["credential_ids"]:
        record = credentials.get(identifier, {})
        _require(record.get("status") == "quarantined"
            and record.get("disconnect_operation_id") == work["work_id"]
            and record.get("quarantine_work_id") == work["work_id"])
    rules = {row["id"]: row for row in catalog["access_rules"]}
    applications = set()
    for identifier in receipt["affected_rule_ids"]:
        record = rules.get(identifier, {})
        _require(record.get("status") == "revoked" and record.get("credential_id") in receipt["credential_ids"])
        applications.add(record["application_id"])
    _require(sorted(applications) == receipt["affected_application_ids"]
        and not any(row["status"] == "active" and row["credential_id"] in receipt["credential_ids"]
            for row in catalog["access_rules"]))
    return item


def require_provider_work(conn, work):
    """Missing/corrupt durable ownership never lends provider-contact authority."""
    item = _work_receipt(conn, work)
    _require(item["status"] in {"pending", "retry"})


def require_terminal_retirement(conn, work):
    """The protected cascade cannot bypass the durable acceptance writer."""
    from catchplate.operator_publication import assert_held
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction)
    assert_held()
    _require(_work_receipt(conn, work)["status"] == "accepted")


def identifies_operation(work_id):
    """Read-only dispatch selection, before the terminal writer acquires EX."""
    from catchplate import db
    if db.metadata_uses_postgres():
        return False
    with db.connect() as conn:
        conn.execute("BEGIN")
        row = conn.execute("SELECT source FROM oauth_revocation_work WHERE id=?", (work_id,)).fetchone()
        if row is not None and row["source"] == SOURCE:
            _require(available(conn) and get(conn, operation_id=work_id) is not None)
            return True
        return False
