"""Operator-only, non-revoking custody for same-account Google reauthorization.

Every writer borrows publication ownership and one SQLite transaction. Token
material lives only in the existing encrypted vault/work envelopes. This owner
never contacts Google, republishes policy, or restores disconnected grants.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid

from catchplate import db, operator_catalog_schema as catalog
from catchplate import operator_google_cleanup_store as cleanup

TABLE = "operator_google_reauthorizations"
SOURCE = "operator_google_reauthorization_v1"
SCHEMA = "catchplate.operatorGoogleReauthorization/v1"
MAX_OPERATIONS = 1024
ADMISSION_ID = "operator-google-reauthorization-schema:v1"
ADMISSION_EVENT = "operator_catalog.oauth.reauthorization_schema_admitted"
ADOPTION_EVENT = "operator_catalog.oauth.reauthorized"
_INSERT = TABLE + "_insert_guard"
_UPDATE = TABLE + "_identity_immutable"
_DELETE = TABLE + "_retained"
_SQL = """CREATE TABLE operator_google_reauthorizations (
    operation_id TEXT PRIMARY KEY, credential_id TEXT NOT NULL, actor_id TEXT NOT NULL,
    status TEXT NOT NULL, binding_json TEXT NOT NULL, state_digest TEXT UNIQUE,
    work_id TEXT UNIQUE, candidate_json TEXT, receipt_json TEXT, reason TEXT) WITHOUT ROWID"""
_INSERT_SQL = """CREATE TRIGGER operator_google_reauthorizations_insert_guard
    BEFORE INSERT ON operator_google_reauthorizations
    WHEN EXISTS (SELECT 1 FROM operator_google_reauthorizations
      WHERE operation_id=NEW.operation_id
        OR (NEW.state_digest IS NOT NULL AND state_digest=NEW.state_digest)
        OR (NEW.work_id IS NOT NULL AND work_id=NEW.work_id))
    BEGIN SELECT RAISE(ABORT,'operator reauthorization already exists'); END"""
_UPDATE_SQL = """CREATE TRIGGER operator_google_reauthorizations_identity_immutable
    BEFORE UPDATE ON operator_google_reauthorizations
    WHEN NEW.operation_id IS NOT OLD.operation_id OR NEW.credential_id IS NOT OLD.credential_id
      OR NEW.actor_id IS NOT OLD.actor_id OR NEW.binding_json IS NOT OLD.binding_json
      OR (OLD.state_digest IS NOT NULL AND NEW.state_digest IS NOT OLD.state_digest)
      OR (OLD.work_id IS NOT NULL AND NEW.work_id IS NOT OLD.work_id)
      OR (OLD.candidate_json IS NOT NULL AND NEW.candidate_json IS NOT OLD.candidate_json)
      OR OLD.status IN ('adopted','denied','expired','failed')
      OR EXISTS (SELECT 1 FROM operator_google_reauthorizations
        WHERE operation_id IS NOT OLD.operation_id
          AND ((NEW.state_digest IS NOT NULL AND state_digest=NEW.state_digest)
            OR (NEW.work_id IS NOT NULL AND work_id=NEW.work_id)))
    BEGIN SELECT RAISE(ABORT,'operator reauthorization binding is immutable'); END"""
_DELETE_SQL = """CREATE TRIGGER operator_google_reauthorizations_retained
    BEFORE DELETE ON operator_google_reauthorizations
    BEGIN SELECT RAISE(ABORT,'operator reauthorization receipt must be retained'); END"""
_DEFINITIONS = ((TABLE, "table", _SQL), (_INSERT, "trigger", _INSERT_SQL),
    (_UPDATE, "trigger", _UPDATE_SQL), (_DELETE, "trigger", _DELETE_SQL))
_STATUSES = {"prepared", "awaiting_consent", "exchanging", "candidate_held", "review_required",
    "adopted", "denied", "expired", "failed"}
_TERMINAL = {"adopted", "denied", "expired", "failed"}
_REASONS = {"start_failed", "state_changed", "consent_denied", "exchange_failed",
    "adoption_uncertain", "identity_mismatch", "candidate_unavailable"}
_BINDING_KEYS = {"operation_id", "credential_id", "actor_id", "name", "provider_id",
    "provider_subject", "provider_account", "oauth_client_id", "scopes", "original_oauth_intent_id",
    "profile_binding_digest", "original_metadata", "expected_revision", "expected_policy_hash",
    "expected_credential_generation", "affected_rule_ids", "application_ids", "assignments_sha256",
    "created_at", "expires_at_epoch"}
_RECEIPT_KEYS = {"schema", "operation_id", "credential_id", "previous_credential_generation",
    "credential_generation", "original_oauth_intent_id", "revision", "policy_hash",
    "affected_rule_ids", "application_ids", "adopted_at"}


class ReauthorizationUnavailable(RuntimeError):
    """Fixed failure; no supplied values, tokens or provider errors."""


def _require(value):
    if not value:
        raise ReauthorizationUnavailable("operator Google reauthorization unavailable")


def _transaction(conn):
    from catchplate.operator_publication import assert_held
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction
        and not db.metadata_uses_postgres() and not db.audit_uses_postgres())
    assert_held()
    cleanup._profile()


def _objects(conn):
    return {row["name"]: dict(row) for row in conn.execute(
        "SELECT name,type,tbl_name,sql FROM sqlite_master WHERE name IN (?,?,?,?) "
        "OR (type='trigger' AND tbl_name=?)", (TABLE, _INSERT, _UPDATE, _DELETE, TABLE))}


def _audit(conn, identifier, event_type, *, expected=None):
    row = conn.execute("SELECT * FROM audit_events WHERE id=?", (identifier,)).fetchone()
    _require(row is not None and row["event_type"] == event_type and row["actor_type"] == "admin"
        and row["event_hash"] == db._audit_hash(event_id=row["id"], event_type=row["event_type"],
            actor_type=row["actor_type"], actor_id=row["actor_id"], event_json=row["event_json"],
            prev_event_hash=row["prev_event_hash"], created_at=row["created_at"]))
    event = cleanup._json(row["event_json"], 65536)
    _require(expected is None or event == expected)
    return row, event


def available(conn):
    from catchplate.operator_catalog_google import validate_profile_binding
    _require(isinstance(conn, sqlite3.Connection))
    profile = validate_profile_binding(conn)
    objects = _objects(conn)
    marker = conn.execute("SELECT 1 FROM audit_events WHERE id=?", (ADMISSION_ID,)).fetchone()
    if not objects:
        _require(marker is None and conn.execute(
            "SELECT 1 FROM oauth_revocation_work WHERE source=? LIMIT 1", (SOURCE,)).fetchone() is None)
        if cleanup._exists(conn):
            _require(conn.execute("SELECT 1 FROM " + cleanup.TABLE + " WHERE source=? LIMIT 1",
                (SOURCE,)).fetchone() is None)
        return False
    _require(profile is not None and set(objects) == {name for name, _, _ in _DEFINITIONS})
    for name, kind, definition in _DEFINITIONS:
        row = objects[name]
        _require(row["type"] == kind and row["tbl_name"] == TABLE
            and " ".join(row["sql"].split()) == " ".join(definition.split()))
    row, admission = _audit(conn, ADMISSION_ID, ADMISSION_EVENT)
    _require(set(admission) == {"schema", "admission_id", "actor_id", "profile_binding_digest",
        "owner_schema_sha256", "revision", "policy_hash", "mode"}
        and admission["schema"] == "catchplate.operatorGoogleReauthorizationAdmission/v1"
        and cleanup._uuid(admission["admission_id"]) and admission["actor_id"] == row["actor_id"]
        and admission["profile_binding_digest"] == profile.binding_digest
        and admission["owner_schema_sha256"] == cleanup._digest([item[2] for item in _DEFINITIONS])
        and admission["mode"] in {"fresh", "upgrade"}
        and type(admission["revision"]) is int and admission["revision"] >= 1
        and isinstance(admission["policy_hash"], str) and cleanup._SHA.fullmatch(admission["policy_hash"]))
    return True


def _catalog_snapshot(conn):
    from catchplate import operator_catalog_google, operator_catalog_policy
    profile = operator_catalog_google.validate_profile_binding(conn)
    _require(profile is not None and cleanup._exists(conn))
    value = catalog.read_catalog(conn)
    catalog.validate_bindings(conn, value)
    operator_catalog_policy.verify_retained_policy(conn, value)
    state = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
    _require(state is not None)
    return profile, value, state["policy_hash"]


def _install(conn, *, actor_id, mode, profile, revision, policy_hash):
    _transaction(conn)
    _require(not available(conn) and isinstance(actor_id, str) and 1 <= len(actor_id) <= 512)
    for _, _, definition in _DEFINITIONS:
        conn.execute(definition)
    receipt = {"schema": "catchplate.operatorGoogleReauthorizationAdmission/v1",
        "admission_id": str(uuid.uuid4()), "actor_id": actor_id, "profile_binding_digest": profile.binding_digest,
        "owner_schema_sha256": cleanup._digest([item[2] for item in _DEFINITIONS]),
        "revision": revision, "policy_hash": policy_hash, "mode": mode}
    db.append_audit_event(conn, event_type=ADMISSION_EVENT, actor_type="admin", actor_id=actor_id,
        event=receipt, idempotency_key=ADMISSION_ID)
    _require(available(conn))
    return receipt


def initialize(conn, *, fresh_profile):
    _transaction(conn)
    _require(type(fresh_profile) is bool)
    if fresh_profile:
        if catalog.active(conn):
            profile, value, policy_hash = _catalog_snapshot(conn)
        else:
            # Profile initialization precedes the catalog's first DDL. The
            # outer startup transaction still validates/imports the complete
            # catalog before COMMIT; admission cannot escape a failed import.
            from catchplate import operator_catalog_google, policy_bundle
            profile = operator_catalog_google.validate_profile_binding(conn)
            state = conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone()
            _require(profile is not None and state is not None)
            snapshot = policy_bundle.compile_policy_bundle(cleanup._json(state["signed_bundle_json"], 4 * 1024 * 1024),
                verify_signature=True, validate_schema=True)
            _require(snapshot.hash == state["policy_hash"])
            value, policy_hash = {"revision": 1}, state["policy_hash"]
        return _install(conn, actor_id="operator-startup", mode="fresh", profile=profile,
            revision=value["revision"], policy_hash=policy_hash)
    available(conn)  # Genuine older absence is unavailable, never reconstructed.


def upgrade(conn, *, expected_revision, expected_policy_hash, profile_binding_digest, actor_id):
    _transaction(conn)
    profile, value, policy_hash = _catalog_snapshot(conn)
    if (value["revision"] != expected_revision or policy_hash != expected_policy_hash
            or profile.binding_digest != profile_binding_digest):
        raise catalog.CatalogConflict()
    return _install(conn, actor_id=actor_id, mode="upgrade", profile=profile,
        revision=value["revision"], policy_hash=policy_hash)


def observe_upgrade(conn, expected_receipt):
    _require(available(conn))
    _audit(conn, ADMISSION_ID, ADMISSION_EVENT, expected=expected_receipt)
    return expected_receipt


def _ids(value):
    return (isinstance(value, list) and len(value) <= 64
        and all(cleanup._uuid(item) for item in value) and value == sorted(set(value)))


def _read(row):
    _require(row is not None)
    binding = cleanup._json(row["binding_json"], 65536)
    _require(isinstance(binding, dict) and set(binding) == _BINDING_KEYS
        and binding["operation_id"] == row["operation_id"] and cleanup._uuid(row["operation_id"])
        and binding["credential_id"] == row["credential_id"] and cleanup._uuid(row["credential_id"])
        and binding["actor_id"] == row["actor_id"] and isinstance(row["actor_id"], str)
        and 1 <= len(row["actor_id"]) <= 512 and row["status"] in _STATUSES
        and binding["provider_id"] == "google" and cleanup._uuid(binding["original_oauth_intent_id"])
        and type(binding["expected_revision"]) is int and binding["expected_revision"] >= 1
        and type(binding["expected_credential_generation"]) is int and binding["expected_credential_generation"] >= 1
        and type(binding["expires_at_epoch"]) is int and isinstance(binding["original_metadata"], dict)
        and _ids(binding["affected_rule_ids"]) and _ids(binding["application_ids"])
        and row["reason"] in _REASONS | {None})
    for field in ("profile_binding_digest", "expected_policy_hash", "assignments_sha256"):
        _require(isinstance(binding[field], str) and cleanup._SHA.fullmatch(binding[field]))
    for field, maximum in (("name", 128), ("provider_subject", 256), ("provider_account", 256),
            ("oauth_client_id", 256), ("created_at", 64)):
        text = binding[field]
        _require(isinstance(text, str) and 1 <= len(text) <= maximum
            and not any(ord(char) < 32 or ord(char) == 127 for char in text))
    _require(binding["scopes"] == list(cleanup._profile().scopes))
    _require(row["state_digest"] is None or isinstance(row["state_digest"], str) and cleanup._SHA.fullmatch(row["state_digest"]))
    _require(row["work_id"] is None or cleanup._uuid(row["work_id"]))
    candidate = cleanup._json(row["candidate_json"], 32768) if row["candidate_json"] is not None else None
    receipt = cleanup._json(row["receipt_json"], 16384) if row["receipt_json"] is not None else None
    _require(candidate is None or isinstance(candidate, dict))
    _require((row["status"] == "adopted") == (receipt is not None))
    if receipt is not None:
        _require(set(receipt) == _RECEIPT_KEYS
            and receipt["schema"] == "catchplate.operatorGoogleReauthorizationReceipt/v1"
            and receipt["operation_id"] == row["operation_id"] and receipt["credential_id"] == row["credential_id"]
            and receipt["previous_credential_generation"] == binding["expected_credential_generation"]
            and type(receipt["credential_generation"]) is int
            and receipt["credential_generation"] == binding["expected_credential_generation"] + 1
            and receipt["original_oauth_intent_id"] == binding["original_oauth_intent_id"]
            and receipt["revision"] == binding["expected_revision"]
            and receipt["policy_hash"] == binding["expected_policy_hash"]
            and receipt["affected_rule_ids"] == binding["affected_rule_ids"]
            and receipt["application_ids"] == binding["application_ids"])
    _require(row["status"] not in {"exchanging", "candidate_held", "review_required", "adopted"}
        or row["work_id"] is not None and row["state_digest"] is not None)
    _require(row["status"] not in {"candidate_held", "adopted"} or candidate is not None)
    return {"operation_id": row["operation_id"], "credential_id": row["credential_id"],
        "actor_id": row["actor_id"], "status": row["status"], "binding": binding,
        "state_digest": row["state_digest"], "work_id": row["work_id"],
        "candidate_metadata": candidate, "receipt": receipt, "reason": row["reason"]}


def get(conn, operation_id, actor_id):
    _require(available(conn) and cleanup._uuid(operation_id))
    row = conn.execute("SELECT * FROM " + TABLE + " WHERE operation_id=? AND actor_id=?",
        (operation_id, actor_id)).fetchone()
    return None if row is None else _read(row)


def _rows(conn):
    if not available(conn):
        return []
    rows = conn.execute("SELECT * FROM " + TABLE + " ORDER BY operation_id LIMIT ?", (MAX_OPERATIONS + 1,)).fetchall()
    _require(len(rows) <= MAX_OPERATIONS)
    return [_read(row) for row in rows]


def status_for_credential(conn, credential_id, actor_id):
    _require(cleanup._uuid(credential_id))
    return [item for item in _rows(conn) if item["credential_id"] == credential_id and item["actor_id"] == actor_id]


def _live(item):
    return (item["status"] not in _TERMINAL and (item["work_id"] is not None
        or item["binding"]["expires_at_epoch"] > int(time.time())))


def require_initial_admission(conn):
    _check_owned_work(conn)
    if any(_live(item) for item in _rows(conn)):
        raise catalog.CatalogConflict()


def require_refresh_admission(conn, credential_id):
    _check_owned_work(conn)
    if any(item["credential_id"] == credential_id and item["work_id"] is not None
            and item["status"] != "adopted" for item in _rows(conn)):
        raise catalog.CatalogConflict()


def _check_owned_work(conn):
    """An orphaned candidate does not release its durable admission barrier."""
    if not available(conn):
        return
    rows = conn.execute("SELECT id FROM oauth_revocation_work WHERE source=? UNION "
        "SELECT work_id AS id FROM " + cleanup.TABLE + " WHERE source=? LIMIT ?",
        (SOURCE, SOURCE, MAX_OPERATIONS + 1)).fetchall()
    _require(len(rows) <= MAX_OPERATIONS)
    for row in rows:
        work = cleanup.get_work(row["id"], conn=conn)
        _require(work is not None)
        require_work(conn, work)
    retained = {row["id"] for row in rows}
    for item in _rows(conn):
        _require(item["work_id"] is None or item["status"] == "adopted" or item["work_id"] in retained)


def _quiescent(conn, metadata, *, own_operation=None, own_work=None):
    from catchplate import operator_catalog_oauth as consent, operator_google_disconnect_store as disconnects
    disconnects.require_refresh_admission(conn, metadata)
    for item in _rows(conn):
        if item["operation_id"] != own_operation and _live(item):
            # Google consent may choose a different account. Do not allow two
            # unknown-account exchanges to evade family custody by target ID.
            raise catalog.CatalogConflict()
    intents = conn.execute("SELECT * FROM operator_catalog_oauth_intents LIMIT ?",
        (consent.MAX_RETAINED_INTENTS + 1,)).fetchall()
    _require(len(intents) <= consent.MAX_RETAINED_INTENTS)
    for row in intents:
        value = consent._read(row)
        if value["status"] == "exchanging" or (value["status"] in {"prepared", "awaiting_consent"}
                and value["expires_at_epoch"] > int(time.time())):
            raise catalog.CatalogConflict()
    family = db._google_oauth_grant_family(metadata)
    rows = conn.execute("SELECT id FROM oauth_revocation_work WHERE provider_id='google' LIMIT ?",
        (cleanup.MAX_FAMILY_SCAN + 1,)).fetchall()
    _require(len(rows) <= cleanup.MAX_FAMILY_SCAN)
    for row in rows:
        if row["id"] == own_work:
            continue
        work = cleanup.get_work(row["id"], conn=conn)
        if work is not None and work["source"] == SOURCE:
            require_work(conn, work)
        if work is None or work["identity"] is None or db._google_oauth_grant_families_collide(family,
                (work["association"]["oauth_client_id"], work["identity"]["provider_subject"])):
            raise catalog.CatalogConflict()


def _target(conn, credential_id):
    from catchplate import operator_catalog_google as google
    profile, value, policy_hash = _catalog_snapshot(conn)
    records = [item for item in value["credentials"] if item["id"] == credential_id]
    if len(records) != 1 or records[0].get("auth_type") != "google_oauth" or records[0]["status"] != "active":
        raise catalog.CatalogConflict()
    core = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    metadata = google.validate_record(records[0], core, profile)
    _require(type(core["credential_version"]) is int and core["credential_version"] >= 1)
    floor = conn.execute("SELECT last_version FROM credential_generations WHERE credential_id=?", (credential_id,)).fetchone()
    _require(floor is not None and floor["last_version"] == core["credential_version"])
    rules = [item for item in value["access_rules"] if item["credential_id"] == credential_id]
    all_application_ids = {item["application_id"] for item in rules}
    applications = [item for item in value["applications"] if item["id"] in all_application_ids]
    application_ids = sorted({item["application_id"] for item in rules if item["status"] == "active"})
    active_ids = sorted(item["id"] for item in rules if item["status"] == "active")
    _require(len(active_ids) <= 64 and len(application_ids) <= 64)
    assignments = {"credential": records[0], "rules": sorted(rules, key=lambda item: item["id"]),
        "applications": sorted(applications, key=lambda item: item["id"])}
    return profile, value, policy_hash, records[0], core, metadata, active_ids, application_ids, cleanup._digest(assignments)


def review(conn, credential_id, actor_id):
    _require(available(conn) and cleanup._uuid(credential_id) and isinstance(actor_id, str) and 1 <= len(actor_id) <= 512)
    profile, value, policy_hash, record, core, metadata, rules, applications, _ = _target(conn, credential_id)
    eligible = True
    try:
        _quiescent(conn, metadata)
    except catalog.CatalogConflict:
        eligible = False
    return {"schema": "catchplate.operatorGoogleReauthorizationReview/v1", "credential_id": credential_id,
        "name": record["name"], "provider_id": "google", "provider_subject": record["provider_subject"],
        "provider_account": record["provider_account"], "oauth_client_id": profile.client_id,
        "scopes": list(profile.scopes), "original_oauth_intent_id": record["oauth_intent_id"],
        "expected_revision": value["revision"], "expected_policy_hash": policy_hash,
        "expected_credential_generation": core["credential_version"], "affected_rule_ids": rules,
        "application_ids": applications, "eligible": eligible}


def begin(conn, payload, actor_id, *, managed_readiness=None):
    _transaction(conn)
    data = payload.model_dump() if hasattr(payload, "model_dump") else payload
    _require(isinstance(data, dict) and set(data) == {"operation_id", "credential_id", "expected_revision",
        "expected_policy_hash", "expected_credential_generation", "affected_rule_ids"}
        and cleanup._uuid(data["operation_id"]) and _ids(data["affected_rule_ids"]))
    current = review(conn, data["credential_id"], actor_id)
    if not current["eligible"]:
        raise catalog.CatalogConflict()
    for key in ("expected_revision", "expected_policy_hash", "expected_credential_generation", "affected_rule_ids"):
        if type(data[key]) is not type(current[key]) or data[key] != current[key]:
            raise catalog.CatalogConflict()
    from catchplate import operator_google_managed_readiness as readiness
    # This is a local-only join after the existing review CAS, not another
    # gate request. Managed callers cannot omit the captured start observation.
    readiness.require_start(conn, managed_readiness)
    _require(len(_rows(conn)) < MAX_OPERATIONS)
    if conn.execute("SELECT 1 FROM " + TABLE + " WHERE operation_id=?", (data["operation_id"],)).fetchone():
        raise catalog.CatalogConflict()
    profile, _, _, _, _, metadata, _, _, assignments = _target(conn, data["credential_id"])
    from catchplate.config import OAUTH_STATE_TTL_SECONDS
    binding = {key: value for key, value in current.items() if key not in {"schema", "eligible"}}
    binding.update(operation_id=data["operation_id"], actor_id=actor_id, profile_binding_digest=profile.binding_digest,
        original_metadata=metadata, assignments_sha256=assignments, created_at=db.iso_now(),
        expires_at_epoch=int(time.time()) + OAUTH_STATE_TTL_SECONDS)
    raw = cleanup._canonical(binding)
    _require(len(raw.encode("ascii")) <= 65536)
    conn.execute("INSERT INTO " + TABLE + " (operation_id,credential_id,actor_id,status,binding_json) VALUES (?,?,?,'prepared',?)",
        (data["operation_id"], data["credential_id"], actor_id, raw))
    db.append_audit_event(conn, event_type="operator_catalog.oauth.reauthorization_started", actor_type="admin",
        actor_id=actor_id, event={"operation_id": data["operation_id"], "credential_id": data["credential_id"],
            "credential_generation": current["expected_credential_generation"], "affected_rule_ids": current["affected_rule_ids"],
            "revision": current["expected_revision"], "policy_hash": current["expected_policy_hash"]})
    return get(conn, data["operation_id"], actor_id)


def _checked(conn, operation_id, actor_id, statuses, *, current=True, reserved_work=None):
    item = get(conn, operation_id, actor_id)
    if item is None or item["status"] not in statuses:
        raise catalog.CatalogConflict()
    binding = item["binding"]
    if current:
        profile, value, policy_hash, _, core, metadata, rules, applications, assignments = _target(conn, item["credential_id"])
        if (profile.binding_digest != binding["profile_binding_digest"] or value["revision"] != binding["expected_revision"]
                or policy_hash != binding["expected_policy_hash"] or core["credential_version"] != binding["expected_credential_generation"]
                or metadata != binding["original_metadata"] or assignments != binding["assignments_sha256"]
                or rules != binding["affected_rule_ids"] or applications != binding["application_ids"]):
            raise catalog.CatalogConflict()
        _quiescent(conn, metadata, own_operation=operation_id, own_work=reserved_work or item["work_id"])
    return item


def bind_started(conn, operation_id, actor_id, *, state_digest, expires_at_epoch):
    _transaction(conn)
    item = _checked(conn, operation_id, actor_id, {"prepared"})
    _require(isinstance(state_digest, str) and cleanup._SHA.fullmatch(state_digest)
        and type(expires_at_epoch) is int and int(time.time()) < expires_at_epoch <= item["binding"]["expires_at_epoch"])
    conn.execute("UPDATE " + TABLE + " SET status='awaiting_consent',state_digest=? WHERE operation_id=?",
        (state_digest, operation_id))
    return get(conn, operation_id, actor_id)


def claim(conn, operation_id, actor_id, *, state_digest):
    _transaction(conn)
    item = _checked(conn, operation_id, actor_id, {"awaiting_consent"})
    if item["state_digest"] != state_digest or item["binding"]["expires_at_epoch"] <= int(time.time()):
        raise catalog.CatalogConflict()
    binding = item["binding"]
    association = {"schema": cleanup.ASSOCIATION_SCHEMA, "operation": "reauthorization", "work_id": None,
        "source": SOURCE, "actor_id": actor_id, "profile_binding_digest": binding["profile_binding_digest"],
        "oauth_client_id": binding["oauth_client_id"], "intent_id": binding["original_oauth_intent_id"],
        "credential_id": item["credential_id"], "credential_generation": binding["expected_credential_generation"],
        "credential_metadata_sha256": cleanup._digest(binding["original_metadata"]), "reauthorization_id": operation_id}
    work_id = db.reserve_oauth_revocation_work(provider_id="google", actor_id=actor_id, source=SOURCE,
        _connection=conn, _operator_association=association)
    conn.execute("UPDATE " + TABLE + " SET status='exchanging',work_id=? WHERE operation_id=?", (work_id, operation_id))
    changed = conn.execute("UPDATE oauth_revocation_work SET status='exchange_in_flight',updated_at=? "
        "WHERE id=? AND status='reserved'", (db.iso_now(), work_id)).rowcount
    _require(changed == 1)
    return get(conn, operation_id, actor_id)


def require_reservation(conn, association, *, work_id):
    _transaction(conn)
    row = conn.execute("SELECT * FROM oauth_revocation_work WHERE id=?", (work_id,)).fetchone()
    _require(row is not None and row["source"] == SOURCE and row["status"] == "reserved"
        and row["actor_id"] == association["actor_id"] and row["provider_id"] == "google"
        and row["attempts"] == 0 and row["lease_owner"] is None and row["lease_until"] is None
        and db.decrypt_secret_envelope(row) == "{}" and association["work_id"] == work_id)
    item = _checked(conn, association["reauthorization_id"], association["actor_id"], {"awaiting_consent"},
        reserved_work=work_id)
    binding = item["binding"]
    _require(item["work_id"] is None and association["credential_id"] == item["credential_id"]
        and association["intent_id"] == binding["original_oauth_intent_id"]
        and association["credential_generation"] == binding["expected_credential_generation"]
        and association["credential_metadata_sha256"] == cleanup._digest(binding["original_metadata"]))


def require_work(conn, work, *, statuses=None):
    _require(work["source"] == SOURCE and work["fence"] is None)
    association = work["association"]
    item = get(conn, association["reauthorization_id"], association["actor_id"])
    _require(item is not None and item["work_id"] == work["work_id"]
        and item["status"] in (statuses or {"exchanging", "candidate_held", "review_required"}))
    binding = item["binding"]
    _require(association["credential_id"] == item["credential_id"]
        and association["intent_id"] == binding["original_oauth_intent_id"]
        and association["profile_binding_digest"] == binding["profile_binding_digest"]
        and association["oauth_client_id"] == binding["oauth_client_id"]
        and association["credential_generation"] == binding["expected_credential_generation"]
        and association["credential_metadata_sha256"] == cleanup._digest(binding["original_metadata"]))
    return item


def stage_candidate(conn, operation_id, actor_id, *, metadata):
    _transaction(conn)
    item = _checked(conn, operation_id, actor_id, {"exchanging"})
    work = cleanup.get_work(item["work_id"], conn=conn)
    _require(work is not None and work["status"] == "held" and work["material_sha256"] is not None)
    require_work(conn, work)
    binding = item["binding"]
    _require(isinstance(metadata, dict))
    original = binding["original_metadata"]
    mutable = {"expires_at_epoch_ms", "refresh_token_expires_at_epoch_ms", "token_type"}
    # The callback actor and new operation ID never become enrollment identity.
    _require({key: value for key, value in metadata.items() if key not in mutable}
        == {key: value for key, value in original.items() if key not in mutable})
    _require(type(metadata.get("expires_at_epoch_ms")) is int
        and metadata["expires_at_epoch_ms"] > time.time_ns() // 1_000_000)
    row = conn.execute("SELECT * FROM oauth_revocation_work WHERE id=?", (item["work_id"],)).fetchone()
    secret = cleanup._json(db.decrypt_secret_envelope(row), 1024 * 1024)
    tokens = cleanup._tokens(secret)
    _require("access_token" in tokens and "refresh_token" in tokens
        and cleanup._digest(tokens) == work["material_sha256"]
        and secret.get("expires_at_epoch_ms") == metadata["expires_at_epoch_ms"]
        and secret.get("refresh_token_expires_at_epoch_ms") == metadata.get("refresh_token_expires_at_epoch_ms"))
    from catchplate.operator_catalog_oauth import canonical_granted_scopes
    _require(canonical_granted_scopes(secret.get("scope")) == binding["scopes"])
    cleanup._bind_identity(conn, item["work_id"], metadata)
    conn.execute("UPDATE " + TABLE + " SET candidate_json=?,status='candidate_held' WHERE operation_id=?",
        (cleanup._canonical(metadata), operation_id))
    return get(conn, operation_id, actor_id)


def adoption_inputs(conn, operation_id, actor_id):
    _transaction(conn)
    item = _checked(conn, operation_id, actor_id, {"candidate_held"})
    work = cleanup.get_work(item["work_id"], conn=conn)
    _require(work is not None and work["status"] == "held" and work["identity"] is not None)
    require_work(conn, work, statuses={"candidate_held"})
    _require(work["identity"] == {key: item["binding"][key] for key in ("provider_subject", "provider_account")})
    row = conn.execute("SELECT * FROM oauth_revocation_work WHERE id=?", (item["work_id"],)).fetchone()
    _require(row is not None and row["lease_owner"] is None and row["lease_until"] is None and row["attempts"] == 0)
    secret = db.decrypt_secret_envelope(row)
    _require(cleanup._digest(cleanup._tokens(secret)) == work["material_sha256"]
        and type(item["candidate_metadata"].get("expires_at_epoch_ms")) is int
        and item["candidate_metadata"]["expires_at_epoch_ms"] > time.time_ns() // 1_000_000)
    return item, secret, item["candidate_metadata"]


def adopt(conn, operation_id, actor_id):
    _transaction(conn)
    item, _, _ = adoption_inputs(conn, operation_id, actor_id)
    db.adopt_operator_google_reauthorization(conn, operation_id=operation_id, actor_id=actor_id)
    binding = item["binding"]
    receipt = {"schema": "catchplate.operatorGoogleReauthorizationReceipt/v1", "operation_id": operation_id,
        "credential_id": item["credential_id"], "previous_credential_generation": binding["expected_credential_generation"],
        "credential_generation": binding["expected_credential_generation"] + 1,
        "original_oauth_intent_id": binding["original_oauth_intent_id"], "revision": binding["expected_revision"],
        "policy_hash": binding["expected_policy_hash"], "affected_rule_ids": binding["affected_rule_ids"],
        "application_ids": binding["application_ids"], "adopted_at": db.iso_now()}
    event_id = "operator-google-reauthorized:" + operation_id
    _require(conn.execute("SELECT 1 FROM audit_events WHERE id=?", (event_id,)).fetchone() is None)
    db.append_audit_event(conn, event_type=ADOPTION_EVENT, actor_type="admin", actor_id=actor_id,
        event=receipt, idempotency_key=event_id)
    conn.execute("UPDATE " + TABLE + " SET status='adopted',receipt_json=?,reason=NULL WHERE operation_id=?",
        (cleanup._canonical(receipt), operation_id))
    cleanup.retire_reauthorization(conn, item["work_id"], operation_id=operation_id, actor_id=actor_id)
    observe_adoption(conn, operation_id, actor_id, expected_receipt=receipt)
    return receipt


def require_retirement(conn, work, *, operation_id, actor_id):
    _transaction(conn)
    item = require_work(conn, work, statuses={"adopted"})
    _require(item["operation_id"] == operation_id and item["actor_id"] == actor_id)
    _audit(conn, "operator-google-reauthorized:" + operation_id, ADOPTION_EVENT, expected=item["receipt"])
    core = conn.execute("SELECT * FROM credentials WHERE id=?", (item["credential_id"],)).fetchone()
    _require(core is not None and core["credential_version"] == item["receipt"]["credential_generation"]
        and cleanup._json(core["metadata"], 32768) == item["candidate_metadata"]
        and cleanup._digest(cleanup._tokens(db.decrypt_secret_envelope(core))) == work["material_sha256"])


def observe_adoption(conn, operation_id, actor_id, expected_receipt=None):
    item = get(conn, operation_id, actor_id)
    _require(item is not None and item["status"] == "adopted" and item["receipt"] is not None
        and (expected_receipt is None or item["receipt"] == expected_receipt))
    row, _ = _audit(conn, "operator-google-reauthorized:" + operation_id, ADOPTION_EVENT, expected=item["receipt"])
    _require(row["actor_id"] == actor_id and cleanup.get_work(item["work_id"], conn=conn) is None
        and conn.execute("SELECT 1 FROM oauth_revocation_work WHERE id=?", (item["work_id"],)).fetchone() is None
        and conn.execute("SELECT 1 FROM " + cleanup.TABLE + " WHERE work_id=?", (item["work_id"],)).fetchone() is None)
    # The retained receipt proves that adoption committed, not current token
    # health: later legitimate refresh/revocation does not erase this history.
    return item


def fail(conn, operation_id, actor_id, *, reason):
    _transaction(conn)
    _require(reason in _REASONS)
    item = _checked(conn, operation_id, actor_id, _STATUSES - _TERMINAL, current=False)
    status = "review_required" if item["work_id"] is not None else ("denied" if reason == "consent_denied" else "failed")
    conn.execute("UPDATE " + TABLE + " SET status=?,reason=? WHERE operation_id=?", (status, reason, operation_id))
    db.append_audit_event(conn, event_type="operator_catalog.oauth.reauthorization_failed", actor_type="admin",
        actor_id=actor_id, event={"operation_id": operation_id, "credential_id": item["credential_id"],
            "status": status, "reason": reason, "provider_revocation": "not_requested"})
    return get(conn, operation_id, actor_id)


def public(item):
    binding = item["binding"]
    status = item["status"]
    if item["work_id"] is None and status in {"prepared", "awaiting_consent"} and binding["expires_at_epoch"] <= int(time.time()):
        status = "expired"
    keys = ("name", "provider_id", "provider_account", "scopes", "created_at", "expires_at_epoch",
        "expected_revision", "expected_policy_hash", "expected_credential_generation", "affected_rule_ids", "application_ids")
    return {"schema": SCHEMA, "operation_id": item["operation_id"], "credential_id": item["credential_id"],
        **{key: binding[key] for key in keys}, "status": status, "reason": item["reason"], "receipt": item["receipt"]}
