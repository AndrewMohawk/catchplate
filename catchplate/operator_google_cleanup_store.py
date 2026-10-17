"""SQLite-only durable ownership for operator Google cleanup work.

No provider transport lives here. The ordinary work row retains encrypted token
material; this bounded side table contains only public associations and fence
receipts. Source tags remain authoritative even if the association disappears.
"""
from __future__ import annotations

from contextlib import closing
from contextvars import ContextVar
import hashlib
import hmac
import json
import re
import sqlite3
import uuid

PREFIX = "operator_google_"
INITIAL_SOURCE = PREFIX + "initial_v1"
REFRESH_SOURCE = PREFIX + "refresh_v1"
DISCONNECT_SOURCE = PREFIX + "disconnect_v1"
REAUTHORIZATION_SOURCE = PREFIX + "reauthorization_v1"
SOURCES = frozenset({INITIAL_SOURCE, REFRESH_SOURCE, DISCONNECT_SOURCE, REAUTHORIZATION_SOURCE})
TABLE = "operator_google_cleanup_work"
_PROFILE_TABLE = "operator_catalog_oauth_profile"
_RETIRE_FUNCTION = "operator_google_cleanup_retire_allowed"
_INSERT_GUARD = "operator_google_cleanup_insert_guard"
_UPDATE_GUARD = "operator_google_cleanup_association_immutable"
_DELETE_GUARD = "operator_google_cleanup_retirement_guard"
_OLD_CORE_GUARD = "operator_google_cleanup_source_immutable"
_RETIRING = ContextVar("operator_google_cleanup_retiring", default=False)
_TABLE_SQL = """CREATE TABLE operator_google_cleanup_work (
    work_id TEXT NOT NULL PRIMARY KEY REFERENCES oauth_revocation_work(id) ON DELETE CASCADE,
    source TEXT NOT NULL, association_json TEXT NOT NULL,
    identity_json TEXT, material_sha256 TEXT, fence_json TEXT,
    created_at TEXT NOT NULL) WITHOUT ROWID"""
_INSERT_SQL = """CREATE TRIGGER operator_google_cleanup_insert_guard
    BEFORE INSERT ON operator_google_cleanup_work
    WHEN EXISTS (SELECT 1 FROM operator_google_cleanup_work WHERE work_id=NEW.work_id)
    BEGIN SELECT RAISE(ABORT,'operator cleanup owner already exists'); END"""
_UPDATE_SQL = """CREATE TRIGGER operator_google_cleanup_association_immutable
    BEFORE UPDATE ON operator_google_cleanup_work
    WHEN NEW.work_id IS NOT OLD.work_id OR NEW.source IS NOT OLD.source
      OR NEW.association_json IS NOT OLD.association_json OR NEW.created_at IS NOT OLD.created_at
      OR (OLD.identity_json IS NOT NULL AND NEW.identity_json IS NOT OLD.identity_json)
      OR (OLD.fence_json IS NOT NULL AND (NEW.fence_json IS NOT OLD.fence_json OR NEW.material_sha256 IS NOT OLD.material_sha256))
    BEGIN SELECT RAISE(ABORT,'operator cleanup association is immutable'); END"""
_DELETE_SQL = """CREATE TRIGGER operator_google_cleanup_retirement_guard
    BEFORE DELETE ON operator_google_cleanup_work
    WHEN operator_google_cleanup_retire_allowed(OLD.work_id) IS NOT 1
    BEGIN SELECT RAISE(ABORT,'operator cleanup retirement refused'); END"""
ASSOCIATION_SCHEMA = "catchplate.operatorGoogleCleanupAssociation/v1"
FENCE_SCHEMA = "catchplate.operatorGoogleCleanupFence/v1"
MAX_ASSOCIATION_BYTES = 8192
MAX_FAMILY_SCAN = 4096
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ASSOCIATION_FIELDS = frozenset({"schema", "operation", "work_id", "source", "actor_id",
    "profile_binding_digest", "oauth_client_id", "intent_id", "credential_id",
    "credential_generation", "credential_metadata_sha256"})
_FENCE_FIELDS = frozenset({"schema", "work_id", "source", "profile_binding_digest",
    "oauth_client_id", "provider_subject", "provider_account", "policy_hash",
    "catalog_revision", "credential_ids", "fenced_at"})


class CleanupStoreError(ValueError):
    """Fixed failure: no token, provider body or submitted value is exposed."""


def _require(value) -> None:
    if not value:
        raise CleanupStoreError("operator Google cleanup binding refused")


def tagged(source) -> bool:
    return isinstance(source, str) and source.startswith(PREFIX)


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _digest(value) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _uuid(value) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _pairs(values):
    result = {}
    for key, value in values:
        _require(key not in result)
        result[key] = value
    return result


def _json(raw, maximum=MAX_ASSOCIATION_BYTES):
    _require(isinstance(raw, str) and len(raw.encode("utf-8")) <= maximum)
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: _require(False))


def _profile():
    from catchplate.operator_catalog_oauth_profile import require_profile
    from catchplate import db
    _require(not db.metadata_uses_postgres())
    return require_profile()


def _transaction(conn):
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction)


def configure_connection(conn) -> None:
    """No DDL or permission: ordinary parent deletes can resolve the guard."""
    conn.create_function(_RETIRE_FUNCTION, 1, lambda _work_id: 0)


def _objects(conn):
    return {row["name"]: dict(row) for row in conn.execute(
        "SELECT name,type,tbl_name,sql FROM sqlite_master WHERE name IN (?,?,?,?,?) "
        "OR (type='trigger' AND tbl_name=?)",
        (TABLE, _INSERT_GUARD, _UPDATE_GUARD, _DELETE_GUARD, _OLD_CORE_GUARD, TABLE)).fetchall()}


def _exists(conn) -> bool:
    # Retained ownership is inspected even when its profile is disabled or
    # malformed. Absence must never silently turn protected work into legacy.
    from catchplate import db
    if isinstance(conn, db.PostgresMetadataConnection):
        return False
    objects = _objects(conn)
    profile = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (_PROFILE_TABLE,)).fetchone()
    if not objects and profile is None:
        return False
    _require(profile is not None and set(objects) == {TABLE, _INSERT_GUARD, _UPDATE_GUARD, _DELETE_GUARD})
    for name, kind, definition in ((TABLE, "table", _TABLE_SQL),
            (_INSERT_GUARD, "trigger", _INSERT_SQL),
            (_UPDATE_GUARD, "trigger", _UPDATE_SQL), (_DELETE_GUARD, "trigger", _DELETE_SQL)):
        row = objects[name]
        _require(row["type"] == kind and row["tbl_name"] == TABLE and isinstance(row["sql"], str)
            and " ".join(row["sql"].split()) == " ".join(definition.split()))
    return True


def retained_ownership(conn=None) -> bool:
    """Disabled configuration cannot erase durable cleanup ownership."""
    from catchplate import db
    if db.metadata_uses_postgres():
        return False
    if conn is None:
        with closing(db.connect()) as opened:
            opened.execute("BEGIN")
            return retained_ownership(conn=opened)
    if _exists(conn):
        return True
    core = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='oauth_revocation_work'").fetchone()
    return core is not None and conn.execute(
        "SELECT 1 FROM oauth_revocation_work WHERE substr(source,1,16)=? LIMIT 1",
        (PREFIX,)).fetchone() is not None


def initialize(conn, *, fresh_profile=False) -> None:
    from catchplate.operator_publication import assert_held
    _profile()
    _transaction(conn)
    assert_held()
    _require(type(fresh_profile) is bool)
    if fresh_profile:
        # This flag comes from profile-table absence before its creation in
        # this same transaction, never from empty intent or work inventories.
        _require(not _objects(conn) and conn.execute(
            "SELECT 1 FROM oauth_revocation_work WHERE substr(source,1,16)=? LIMIT 1",
            (PREFIX,)).fetchone() is None)
        for definition in (_TABLE_SQL, _INSERT_SQL, _UPDATE_SQL, _DELETE_SQL):
            conn.execute(definition)
    _require(_exists(conn))  # Retained schemas are verified, never repaired.
    from catchplate import operator_google_disconnect_store
    operator_google_disconnect_store.initialize(conn, fresh_profile=fresh_profile)
    from catchplate import operator_google_reauthorization_store
    operator_google_reauthorization_store.initialize(conn, fresh_profile=fresh_profile)


def _association(value, row):
    fields = (_ASSOCIATION_FIELDS | {"reauthorization_id"}
        if row["source"] == REAUTHORIZATION_SOURCE else _ASSOCIATION_FIELDS)
    _require(isinstance(value, dict) and set(value) == fields
        and value["schema"] == ASSOCIATION_SCHEMA and value["source"] in SOURCES
        and value["source"] == row["source"] and value["work_id"] == row["id"]
        and value["actor_id"] == row["actor_id"] and row["provider_id"] == "google"
        and _uuid(value["work_id"]) and _uuid(value["intent_id"])
        and isinstance(value["actor_id"], str) and 1 <= len(value["actor_id"]) <= 512
        and isinstance(value["oauth_client_id"], str) and 1 <= len(value["oauth_client_id"]) <= 256
        and isinstance(value["profile_binding_digest"], str) and _SHA.fullmatch(value["profile_binding_digest"]))
    if value["source"] == INITIAL_SOURCE:
        _require(value["operation"] == "initial" and value["credential_id"] is None
            and value["credential_generation"] is None and value["credential_metadata_sha256"] is None)
    else:
        _require(value["operation"] == {REFRESH_SOURCE: "refresh", DISCONNECT_SOURCE: "disconnect",
            REAUTHORIZATION_SOURCE: "reauthorization"}[value["source"]]
            and _uuid(value["credential_id"])
            and type(value["credential_generation"]) is int and value["credential_generation"] > 0
            and isinstance(value["credential_metadata_sha256"], str)
            and _SHA.fullmatch(value["credential_metadata_sha256"]))
    if value["source"] == REAUTHORIZATION_SOURCE:
        _require(_uuid(value["reauthorization_id"]))
    return value


def get_work(work_id, conn=None):
    from catchplate import db
    if conn is None:
        with closing(db.connect()) as opened:
            opened.execute("BEGIN")
            return get_work(work_id, conn=opened)
    associated = conn.execute("SELECT * FROM " + TABLE + " WHERE work_id=?", (work_id,)).fetchone() if _exists(conn) else None
    row = conn.execute("SELECT id,source,provider_id,actor_id,status FROM oauth_revocation_work WHERE id=?", (work_id,)).fetchone()
    if row is None:
        _require(associated is None)  # An orphan is retained ownership, not legacy.
        return None
    if not tagged(row["source"]) and associated is None:
        return None
    _require(row["source"] in SOURCES and associated is not None and associated["source"] == row["source"])
    association = _association(_json(associated["association_json"]), row)
    identity = _json(associated["identity_json"]) if associated["identity_json"] is not None else None
    if identity is not None:
        _require(isinstance(identity, dict) and set(identity) == {"provider_subject", "provider_account"}
            and all(isinstance(value, str) and 0 < len(value) <= 256
                and not any(ord(char) < 32 or ord(char) == 127 for char in value) for value in identity.values()))
    material = associated["material_sha256"]
    _require(material is None or isinstance(material, str) and _SHA.fullmatch(material))
    fence = _json(associated["fence_json"]) if associated["fence_json"] is not None else None
    _require(row["source"] != REAUTHORIZATION_SOURCE or fence is None)
    if fence is not None:
        _require(isinstance(fence, dict) and set(fence) == _FENCE_FIELDS and fence["schema"] == FENCE_SCHEMA
            and all(fence[key] == association[key] for key in ("work_id", "source", "profile_binding_digest", "oauth_client_id"))
            and identity is not None and all(fence[key] == identity[key] for key in identity)
            and isinstance(fence["policy_hash"], str) and _SHA.fullmatch(fence["policy_hash"])
            and type(fence["catalog_revision"]) is int and fence["catalog_revision"] > 0
            and isinstance(fence["fenced_at"], str) and 1 <= len(fence["fenced_at"]) <= 64
            and isinstance(fence["credential_ids"], list) and len(fence["credential_ids"]) <= MAX_FAMILY_SCAN
            and all(_uuid(identifier) for identifier in fence["credential_ids"])
            and fence["credential_ids"] == sorted(set(fence["credential_ids"])) and material is not None)
    return {"work_id": work_id, "source": row["source"], "status": row["status"],
        "association": association, "identity": identity, "material_sha256": material, "fence": fence}


def _identity(metadata, profile):
    from catchplate import db
    _require(isinstance(metadata, dict) and metadata.get("oauth") is True
        and metadata.get("provider_id") == "google" and metadata.get("provider") == "google.oauth2"
        and metadata.get("provider_identity_verified") is True and metadata.get("oauth_client_id") == profile.client_id)
    provider, subject, account = db.validate_managed_oauth_account_identity(metadata)
    _require(provider == "google")
    return {"provider_subject": subject, "provider_account": account}


def _check_profile(work):
    profile = _profile()
    _require(work["association"]["profile_binding_digest"] == profile.binding_digest
        and work["association"]["oauth_client_id"] == profile.client_id)
    return profile


def _reserve(conn, *, operation, actor_id, profile, intent_id, credential=None):
    from catchplate import db
    _transaction(conn)
    _require(_exists(conn))
    _require(operation in {"initial", "refresh", "disconnect"})
    source = {"initial": INITIAL_SOURCE, "refresh": REFRESH_SOURCE, "disconnect": DISCONNECT_SOURCE}[operation]
    association = {"schema": ASSOCIATION_SCHEMA, "operation": operation, "work_id": None,
        "source": source, "actor_id": actor_id, "profile_binding_digest": profile.binding_digest,
        "oauth_client_id": profile.client_id, "intent_id": intent_id,
        "credential_id": credential["id"] if credential else None,
        "credential_generation": credential["credential_version"] if credential else None,
        "credential_metadata_sha256": _digest(credential["metadata"]) if credential else None}
    return db.reserve_oauth_revocation_work(provider_id="google", actor_id=actor_id, source=source,
        _connection=conn, _operator_association=association)


def reserve_initial(*, intent_id, actor_id):
    from catchplate import db, operator_catalog_oauth as consent
    from catchplate.operator_publication import exclusive
    profile = _profile()
    with exclusive(), db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        consent._checked(conn, intent_id, status="exchanging", actor_id=actor_id)
        work_id = _reserve(conn, operation="initial", actor_id=actor_id, profile=profile, intent_id=intent_id)
        conn.commit()
        return work_id


def reserve_refresh(*, metadata, actor_id):
    from catchplate import db, operator_catalog_schema as schema, operator_catalog_google as google
    profile = _profile()
    with db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        schema.validate_bindings(conn)
        _require(isinstance(metadata, dict))
        matches = [record for record in schema.read_catalog(conn)["credentials"]
            if record.get("auth_type") == "google_oauth" and record.get("oauth_intent_id") == metadata.get("oauth_intent_id")]
        _require(len(matches) == 1)
        row = conn.execute("SELECT id,name,kind,lifecycle_status,metadata,credential_version FROM credentials WHERE id=?", (matches[0]["id"],)).fetchone()
        actual = google.validate_record(matches[0], row, profile)
        _require(actual == metadata and type(row["credential_version"]) is int and row["credential_version"] > 0)
        work_id = _reserve(conn, operation="refresh", actor_id=actor_id, profile=profile,
            intent_id=metadata["oauth_intent_id"], credential={**dict(row), "metadata": actual})
        _bind_identity(conn, work_id, metadata)
        conn.commit()
        return work_id


def on_reserve(conn, *, work_id, provider_id, actor_id, source, association):
    """Called only inside the existing encrypted-work reservation transaction."""
    from catchplate import db, operator_catalog_oauth_profile as profiles
    if not tagged(source):
        _require(association is None)
        if provider_id == "google":
            # Neither disabling the flag nor losing an association grants
            # ordinary fallback work under a retained operator ownership pin.
            _require(not profiles.selected() and not retained_ownership(conn=conn))
        return
    profile = _profile()
    _transaction(conn)
    _require(source in SOURCES and isinstance(association, dict) and _exists(conn))
    value = {**association, "work_id": work_id}
    _association(value, {"id": work_id, "source": source, "provider_id": provider_id, "actor_id": actor_id})
    _require(value["profile_binding_digest"] == profile.binding_digest and value["oauth_client_id"] == profile.client_id)
    # The private DB argument is not itself authority: independently join its
    # asserted association to the caller's real transaction snapshot.
    if source == INITIAL_SOURCE:
        from catchplate import operator_catalog_oauth as consent
        from catchplate import operator_google_disconnect_store as disconnects
        disconnects.require_initial_admission(conn)
        from catchplate import operator_google_reauthorization_store as reauthorization
        reauthorization.require_initial_admission(conn)
        consent._checked(conn, value["intent_id"], status="exchanging", actor_id=actor_id)
    else:
        from catchplate import operator_catalog_schema as schema, operator_catalog_google as google
        schema.validate_bindings(conn)
        records = [item for item in schema.read_catalog(conn)["credentials"] if item["id"] == value["credential_id"]]
        _require(len(records) == 1)
        row = conn.execute("SELECT id,name,kind,lifecycle_status,metadata,credential_version FROM credentials WHERE id=?",
            (value["credential_id"],)).fetchone()
        metadata = google.validate_record(records[0], row, profile)
        _require(metadata.get("oauth_intent_id") == value["intent_id"]
            and row["credential_version"] == value["credential_generation"]
            and _digest(metadata) == value["credential_metadata_sha256"])
        from catchplate import operator_google_disconnect_store as disconnects
        if source == REFRESH_SOURCE:
            disconnects.require_refresh_admission(conn, metadata)
            from catchplate import operator_google_reauthorization_store as reauthorization
            reauthorization.require_refresh_admission(conn, value["credential_id"])
        elif source == REAUTHORIZATION_SOURCE:
            from catchplate import operator_google_reauthorization_store as reauthorization
            reauthorization.require_reservation(conn, value, work_id=work_id)
        else:
            from catchplate.operator_publication import assert_held
            assert_held()
            _require(source == DISCONNECT_SOURCE and disconnects.available(conn))
    raw = _canonical(value)
    _require(len(raw.encode("ascii")) <= MAX_ASSOCIATION_BYTES)
    conn.execute("INSERT INTO " + TABLE + " (work_id,source,association_json,created_at) VALUES (?,?,?,?)",
        (work_id, source, raw, db.iso_now()))


def _bind_identity(conn, work_id, metadata):
    work = get_work(work_id, conn=conn)
    _require(work is not None)
    if work["source"] == REAUTHORIZATION_SOURCE:
        from catchplate import operator_google_reauthorization_store as reauthorization
        reauthorization.require_work(conn, work)
    identity = _identity(metadata, _check_profile(work))
    _require(work["identity"] is None or work["identity"] == identity)
    if work["identity"] is None:
        _require(work["fence"] is None)
        conn.execute("UPDATE " + TABLE + " SET identity_json=? WHERE work_id=?", (_canonical(identity), work_id))
    return identity


def bind_identity(work_id, metadata):
    from catchplate import db
    with db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        value = _bind_identity(conn, work_id, metadata)
        conn.commit()
        return value


def _tokens(secret):
    value = _json(secret, 1024 * 1024) if isinstance(secret, str) else secret
    _require(isinstance(value, dict))
    result = {}
    for key in ("access_token", "refresh_token"):
        if key in value:
            token = value[key]
            _require(isinstance(token, str) and 0 < len(token.encode("utf-8")) <= 128 * 1024)
            result[key] = token
    _require(bool(result))
    token_type = value.get("token_type", "Bearer")
    _require(isinstance(token_type, str) and token_type.lower() == "bearer")
    result["token_type"] = "Bearer"
    return result


def on_attach(conn, work_id, secret):
    work = get_work(work_id, conn=conn)
    if work is None:
        return
    _check_profile(work)
    _require(work["fence"] is None)
    if work["source"] == REAUTHORIZATION_SOURCE:
        from catchplate import operator_google_reauthorization_store as reauthorization
        reauthorization.require_work(conn, work, statuses={"exchanging"})
        _require(work["status"] == "exchange_in_flight" and work["material_sha256"] is None)
    conn.execute("UPDATE " + TABLE + " SET material_sha256=? WHERE work_id=?", (_digest(_tokens(secret)), work_id))


def _fenced_snapshot(conn, work):
    from catchplate import db, operator_catalog_schema as schema, operator_catalog_policy as policy
    _require(work["source"] != REAUTHORIZATION_SOURCE)
    _check_profile(work)
    _require(work["identity"] is not None and work["material_sha256"] is not None)
    schema.validate_bindings(conn)
    catalog = schema.read_catalog(conn)
    records = {record["id"]: record for record in catalog["credentials"]}
    candidate = (work["association"]["oauth_client_id"], work["identity"]["provider_subject"])
    rows = conn.execute("SELECT id,kind,metadata,lifecycle_status FROM credentials LIMIT ?", (MAX_FAMILY_SCAN + 1,)).fetchall()
    _require(len(rows) <= MAX_FAMILY_SCAN)
    identifiers = []
    for row in rows:
        metadata = _json(row["metadata"], 32768)
        family = db._google_oauth_grant_family(metadata)
        if family is None or not db._google_oauth_grant_families_collide(candidate, family):
            continue
        record = records.get(row["id"], {})
        _require(row["lifecycle_status"] == "revocation_pending" and record.get("status") == "quarantined"
            and record.get("auth_type") == "google_oauth" and _uuid(record.get("quarantine_work_id"))
            and record.get("quarantine_reason") == "operator_google_cleanup_fence")
        identifiers.append(row["id"])
    # An empty snapshot is not a durable family exclusion: another consent
    # could issue/adopt that family's tokens while provider cleanup is in
    # flight. Only retained quarantined core rows currently prevent adoption.
    # Empty-family work stays deferred/manual-only, including old empty receipts.
    _require(bool(identifiers))
    pending = conn.execute("SELECT metadata,status FROM pending_oauth_credentials LIMIT ?", (MAX_FAMILY_SCAN + 1,)).fetchall()
    _require(len(pending) <= MAX_FAMILY_SCAN)
    for row in pending:
        family = db._google_oauth_grant_family(_json(row["metadata"], 32768))
        if family is not None and db._google_oauth_grant_families_collide(candidate, family):
            _require(row["status"] != "pending")
    _require(not any(rule["status"] == "active" and rule["credential_id"] in identifiers
        for rule in catalog["access_rules"]))
    policy.verify_retained_policy(conn, catalog)
    state = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
    _require(state is not None)
    return sorted(identifiers), state["policy_hash"], catalog["revision"]


def authorize_fence(conn, *, work_id, metadata, policy_hash, catalog_revision):
    from catchplate import db
    from catchplate.operator_publication import assert_held
    _transaction(conn)
    assert_held()
    work = get_work(work_id, conn=conn)
    _require(work is not None)
    _require(_identity(metadata, _check_profile(work)) == work["identity"])
    identifiers, actual_hash, actual_revision = _fenced_snapshot(conn, work)
    if work["fence"] is not None:
        _require((policy_hash, catalog_revision) in {(actual_hash, actual_revision),
            (work["fence"]["policy_hash"], work["fence"]["catalog_revision"])})
        _require(eligible(conn, {"id": work_id, "source": work["source"]}))
        return work["fence"]
    _require(policy_hash == actual_hash and catalog_revision == actual_revision)
    retained = conn.execute("SELECT * FROM oauth_revocation_work WHERE id=?", (work_id,)).fetchone()
    _require(retained is not None and _digest(_tokens(db.decrypt_secret_envelope(retained))) == work["material_sha256"])
    if work["association"]["operation"] == "initial":
        from catchplate import operator_catalog_oauth as consent
        intent = consent._get(conn, work["association"]["intent_id"])
        _require(intent["status"] == "failed" and intent["actor_id"] == work["association"]["actor_id"]
            and intent["oauth_profile_binding_digest"] == work["association"]["profile_binding_digest"])
    receipt = {"schema": FENCE_SCHEMA, "work_id": work_id, "source": work["source"],
        "profile_binding_digest": work["association"]["profile_binding_digest"],
        "oauth_client_id": work["association"]["oauth_client_id"], **work["identity"],
        "policy_hash": actual_hash, "catalog_revision": actual_revision,
        "credential_ids": identifiers, "fenced_at": db.iso_now()}
    _require(work["status"] in {"held", "pending"})
    raw_receipt = _canonical(receipt)
    _require(len(raw_receipt.encode("ascii")) <= MAX_ASSOCIATION_BYTES)
    conn.execute("UPDATE " + TABLE + " SET fence_json=? WHERE work_id=?", (raw_receipt, work_id))
    conn.execute("UPDATE oauth_revocation_work SET status='pending',next_attempt_at=?,updated_at=? WHERE id=?",
        (db.iso_now(), db.iso_now(), work_id))
    db.append_audit_event(conn, event_type="operator_catalog.oauth.cleanup_fenced", actor_type="admin",
        actor_id=work["association"]["actor_id"], event=receipt)
    return receipt


def _eligible_work(conn, work, *, terminal=False) -> bool:
    _require(work["source"] != REAUTHORIZATION_SOURCE and work["fence"] is not None)
    identifiers, _current_hash, revision = _fenced_snapshot(conn, work)
    if work["source"] == DISCONNECT_SOURCE:
        from catchplate import operator_google_disconnect_store as disconnects
        if terminal:
            disconnects.require_terminal_retirement(conn, work)
        else:
            disconnects.require_provider_work(conn, work)
    return (identifiers == work["fence"]["credential_ids"]
        and revision >= work["fence"]["catalog_revision"])


def eligible(conn, work_row) -> bool:
    """Read-only oracle; malformed operator work stays retained, never legacy."""
    try:
        work = get_work(work_row["id"], conn=conn)
        if work is None:
            return not tagged(work_row["source"])
        return _eligible_work(conn, work)
    except Exception:
        return False


def ordinary_clause(conn) -> str:
    """Ownership presence excludes a row without parsing it or its profile."""
    ordinary = "substr(source,1,16) != 'operator_google_'"
    if _exists(conn):
        ordinary += " AND NOT EXISTS (SELECT 1 FROM " + TABLE + " AS protected " \
            "WHERE protected.work_id=oauth_revocation_work.id)"
    return "(" + ordinary + ")"


def reservation_count(conn, *, exclude=None) -> int:
    where, params = ("", ()) if exclude is None else (" WHERE id<>?", (exclude,))
    if not _exists(conn):
        return int(conn.execute("SELECT COUNT(*) AS count FROM oauth_revocation_work" + where,
            params).fetchone()["count"])
    return int(conn.execute("SELECT COUNT(*) AS count FROM (SELECT id FROM oauth_revocation_work UNION "
        "SELECT work_id AS id FROM " + TABLE + ")" + where, params).fetchone()["count"])


def claim_clause(conn) -> str:
    """Skip withheld work before the bounded ordinary claim LIMIT is applied.

    This is only a candidate filter. Every selected row still passes eligible()
    before its encrypted material is read or a worker lease is assigned.
    """
    ordinary = ordinary_clause(conn)
    if not _exists(conn):
        return ordinary
    return "(" + ordinary + " OR EXISTS (SELECT 1 FROM " + TABLE + " AS protected " \
        "WHERE protected.work_id=oauth_revocation_work.id AND protected.source=oauth_revocation_work.source " \
        "AND protected.fence_json IS NOT NULL))"


def claimed_marker(conn, work_id):
    """Private server-owned marker; never infer ownership from the core tag."""
    work = get_work(work_id, conn=conn)
    if work is None:
        return {}
    _require(eligible(conn, {"id": work_id, "source": work["source"]}))
    return {"operator_google_cleanup_work_id": work_id}


def require_permit(*, work_id, secret):
    from catchplate import db
    with closing(db.connect()) as conn:
        conn.execute("BEGIN")
        work = get_work(work_id, conn=conn)
        _require(work is not None and eligible(conn, {"id": work_id, "source": work["source"]}))
        row = conn.execute("SELECT * FROM oauth_revocation_work WHERE id=?", (work_id,)).fetchone()
        _require(row is not None and row["status"] in {"held", "pending"})
        retained = _digest(_tokens(db.decrypt_secret_envelope(row)))
        supplied = _digest(_tokens(secret))
        _require(hmac.compare_digest(retained, work["material_sha256"])
            and hmac.compare_digest(supplied, retained))
        return work["fence"]


def require_transition(conn, work_id, *, cleanup=False):
    work = get_work(work_id, conn=conn)
    if work is None:
        return
    _check_profile(work)
    if work["source"] == REAUTHORIZATION_SOURCE:
        from catchplate import operator_google_reauthorization_store as reauthorization
        reauthorization.require_work(conn, work)
        _require(not cleanup)
    if cleanup:
        _require(eligible(conn, {"id": work_id, "source": work["source"]}))


def require_quarantine(conn, work_id, *, borrowed, oauth_client_id, provider_subject):
    work = get_work(work_id, conn=conn)
    if work is None:
        return
    _require(work["source"] != REAUTHORIZATION_SOURCE)
    from catchplate.operator_publication import assert_held
    _transaction(conn)
    _require(borrowed)
    assert_held()
    _check_profile(work)
    _require(work["identity"] is not None
        and work["identity"]["provider_subject"] == provider_subject
        and work["association"]["oauth_client_id"] == oauth_client_id)


def require_adoption(conn, work_id, credential_id):
    from catchplate import db
    work = get_work(work_id, conn=conn)
    if work is None:
        return
    _require(work["source"] not in {DISCONNECT_SOURCE, REAUTHORIZATION_SOURCE})
    profile = _check_profile(work)
    _require(_uuid(credential_id) and work["fence"] is None and work["identity"] is not None)
    row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    _require(row is not None and row["kind"] == "oauth2" and row["lifecycle_status"] == "active")
    metadata = _json(row["metadata"], 32768)
    _require(_identity(metadata, profile) == work["identity"]
        and metadata.get("oauth_profile_binding_digest") == profile.binding_digest
        and metadata.get("oauth_intent_id") == work["association"]["intent_id"]
        and metadata.get("scopes") == list(profile.scopes))
    if work["association"]["operation"] == "refresh":
        _require(credential_id == work["association"]["credential_id"]
            and row["credential_version"] in {work["association"]["credential_generation"],
                work["association"]["credential_generation"] + 1})
    retained = conn.execute("SELECT * FROM oauth_revocation_work WHERE id=?", (work_id,)).fetchone()
    issued = _tokens(db.decrypt_secret_envelope(retained))
    adopted = _tokens(db.decrypt_secret_envelope(row))
    _require(_digest(issued) == work["material_sha256"] and all(adopted.get(key) == value for key, value in issued.items()))


def refuse_generic_completion(conn, work_id):
    # An eligible fence is not evidence of adoption or successful provider
    # cleanup. Generic completion/uncertainty APIs have neither authority.
    _require(get_work(work_id, conn=conn) is None)


REJECTION_EVENT = "operator_catalog.oauth.refresh_rejected"


def retire_rejected_refresh(conn, rejection, summary):
    """Retire only a fresh typed denial's unchanged, empty refresh reservation.

    The caller consumed the transport-owned proof before entering this writer;
    this writer separately burns its one-use retirement claim, even on rollback.
    No account material is decrypted or changed; only the empty reservation is
    opened. The audit and protected deletion share this caller's transaction.
    """
    from datetime import datetime
    from catchplate import db, operator_catalog_google as google, operator_catalog_schema as schema
    from catchplate.operator_google_token_response import RejectedRefresh, REJECTION_CODES_BY_STATUS
    from catchplate.operator_publication import assert_held
    _transaction(conn)
    assert_held()
    _require(not db.audit_uses_postgres())
    _require(type(rejection) is RejectedRefresh)
    claimed = rejection.claim_retirement()
    _require(type(claimed) is dict and claimed == summary)
    _require(type(summary) is dict and set(summary) == {"work_id", "profile_binding_digest",
        "oauth_client_id", "http_status", "error_code"} and _uuid(summary["work_id"])
        and type(summary["http_status"]) is int
        and summary["error_code"] in REJECTION_CODES_BY_STATUS.get(summary["http_status"], ()))
    work_id = summary["work_id"]
    work = get_work(work_id, conn=conn)
    _require(work is not None and work["source"] == REFRESH_SOURCE
        and work["status"] == "exchange_in_flight" and work["material_sha256"] is None
        and work["fence"] is None and work["identity"] is not None)
    association = work["association"]
    profile = _check_profile(work)
    _require(summary["profile_binding_digest"] == profile.binding_digest
        and summary["oauth_client_id"] == profile.client_id and association["operation"] == "refresh")
    schema.validate_bindings(conn)
    records = [record for record in schema.read_catalog(conn)["credentials"]
        if record["id"] == association["credential_id"]]
    _require(len(records) == 1)
    core = conn.execute("SELECT id,name,kind,metadata,lifecycle_status,credential_version "
        "FROM credentials WHERE id=?", (association["credential_id"],)).fetchone()
    metadata = google.validate_record(records[0], core, profile)
    _require(core["credential_version"] == association["credential_generation"]
        and _digest(metadata) == association["credential_metadata_sha256"]
        and _identity(metadata, profile) == work["identity"]
        and metadata.get("oauth_intent_id") == association["intent_id"]
        and str(metadata.get("created_by") or "oauth-refresh") == association["actor_id"])
    row = conn.execute("SELECT * FROM oauth_revocation_work WHERE id=?", (work_id,)).fetchone()
    _require(row is not None and row["provider_id"] == "google" and row["source"] == REFRESH_SOURCE
        and row["actor_id"] == association["actor_id"] and row["status"] == "exchange_in_flight"
        and row["credential_version"] == 1 and row["attempts"] == 0 and row["last_error"] is None
        and row["lease_owner"] is None and row["lease_until"] is None
        and datetime.fromisoformat(row["next_attempt_at"]) > db.utcnow()
        and db.decrypt_secret_envelope(row) == "{}")
    event_id = "operator-google-refresh-rejected:" + work_id
    # A pre-existing terminal receipt is not permission to mutate again.
    _require(conn.execute("SELECT 1 FROM audit_events WHERE id=?", (event_id,)).fetchone() is None)
    event = {"schema": "catchplate.operatorGoogleRefreshRejected/v1", **summary,
        "source": REFRESH_SOURCE, "credential_id": association["credential_id"],
        "credential_generation": association["credential_generation"],
        "credential_metadata_sha256": association["credential_metadata_sha256"],
        "provider_subject": work["identity"]["provider_subject"], "outcome": "definite_refresh_rejected",
        "issued_material": False, "provider_revocation": "not_requested"}
    audit = db.append_audit_event(conn, event_type=REJECTION_EVENT,
        actor_type="system", actor_id=association["actor_id"], event=event, idempotency_key=event_id)
    _guarded_delete(conn, work_id, "exchange_in_flight")
    return audit


def observe_rejected_refresh(conn, audit):
    """Exact readback after an attempted COMMIT; absence alone proves nothing."""
    from catchplate import db, operator_catalog_google
    _transaction(conn)
    profile = _profile()
    _require(_exists(conn) and not db.audit_uses_postgres())
    event = audit["event"]
    _require(operator_catalog_google.validate_profile_binding(conn) == profile
        and event["profile_binding_digest"] == profile.binding_digest
        and event["oauth_client_id"] == profile.client_id)
    work_id = event["work_id"]
    _require(_uuid(work_id) and audit["id"] == "operator-google-refresh-rejected:" + work_id
        and audit["event_type"] == REJECTION_EVENT and audit["actor_type"] == "system")
    row = conn.execute("SELECT * FROM audit_events WHERE id=?", (audit["id"],)).fetchone()
    _require(row is not None and row["event_type"] == audit["event_type"]
        and row["actor_type"] == audit["actor_type"] and row["actor_id"] == audit["actor_id"]
        and row["event_json"] == db.dumps(event) and row["event_hash"] == audit["event_hash"]
        and row["prev_event_hash"] == audit["prev_event_hash"] and row["created_at"] == audit["created_at"]
        and row["event_hash"] == db._audit_hash(event_id=row["id"], event_type=row["event_type"],
            actor_type=row["actor_type"], actor_id=row["actor_id"], event_json=row["event_json"],
            prev_event_hash=row["prev_event_hash"], created_at=row["created_at"]))
    _require(get_work(work_id, conn=conn) is None
        and conn.execute("SELECT 1 FROM oauth_revocation_work WHERE id=?", (work_id,)).fetchone() is None
        and conn.execute("SELECT 1 FROM " + TABLE + " WHERE work_id=?", (work_id,)).fetchone() is None)


def retire(conn, work_id, *, credential_id=None, worker_id=None) -> bool:
    """Retire protected work only through a verified, atomic parent cascade.

    Returns False for ordinary work. The persistent operator-side DELETE guard
    denies raw deletes and cascades on every connection, including restart.
    Its one-use callback is armed only around this one parent DELETE statement.
    No provider I/O, commit, durable success ledger, or core-schema DDL occurs.
    """
    from catchplate import db
    work = get_work(work_id, conn=conn)
    if work is None:
        return False
    _require(work["source"] != REAUTHORIZATION_SOURCE)
    _transaction(conn)
    _require(not _RETIRING.get())
    _require((credential_id is None) != (worker_id is None))
    row = conn.execute("SELECT * FROM oauth_revocation_work WHERE id=?", (work_id,)).fetchone()
    _require(row is not None)
    if credential_id is not None:
        _require(row["status"] == "held")
        require_adoption(conn, work_id, credential_id)
    else:
        _require(isinstance(worker_id, str) and worker_id and row["status"] == "pending"
            and row["lease_owner"] == worker_id)
        if work["source"] == DISCONNECT_SOURCE:
            _require(_eligible_work(conn, work, terminal=True))
        else:
            _require(eligible(conn, {"id": work_id, "source": work["source"]}))
        _require(_digest(_tokens(db.decrypt_secret_envelope(row))) == work["material_sha256"])
    return _guarded_delete(conn, work_id, row["status"])


def retire_reauthorization(conn, work_id, *, operation_id, actor_id):
    """Only a same-transaction adopted receipt permits non-revoking retirement."""
    from catchplate import operator_google_reauthorization_store as reauthorization
    _transaction(conn)
    work = get_work(work_id, conn=conn)
    _require(work is not None and work["source"] == REAUTHORIZATION_SOURCE and work["status"] == "held")
    reauthorization.require_retirement(conn, work, operation_id=operation_id, actor_id=actor_id)
    return _guarded_delete(conn, work_id, "held")


def _guarded_delete(conn, work_id, status):
    """Shared one-use cascade after the caller's purpose-specific guards."""
    _transaction(conn)
    _require(not _RETIRING.get())
    used = False
    armed = True

    def allow(identifier):
        nonlocal used
        if armed and not used and identifier == work_id and conn.in_transaction:
            used = True
            return 1
        return 0

    token = _RETIRING.set(True)
    try:
        conn.execute("SAVEPOINT operator_google_cleanup_retire")
        try:
            conn.create_function(_RETIRE_FUNCTION, 1, allow)
            deleted = conn.execute("DELETE FROM oauth_revocation_work WHERE id=? AND status=?",
                (work_id, status))
            _require(deleted.rowcount == 1 and used
                and conn.execute("SELECT 1 FROM " + TABLE + " WHERE work_id=?", (work_id,)).fetchone() is None)
        except BaseException:
            conn.execute("ROLLBACK TO SAVEPOINT operator_google_cleanup_retire")
            raise
        finally:
            armed = False
            configure_connection(conn)
            conn.execute("RELEASE SAVEPOINT operator_google_cleanup_retire")
    finally:
        armed = False
        _RETIRING.reset(token)
    return True
