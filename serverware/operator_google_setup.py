"""Reviewed, public-only first Google enablement on a retained operator store.

Preparation never edits settings, loads a client secret, or contacts a provider.
Cold activation consumes the exact pending review in the caller's publication
transaction; it preserves resource rows and signed policy, not stale reviews.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3

from pydantic import Field, field_validator

from serverware import db, operator_catalog_schema as catalog
from serverware import operator_catalog_oauth_profile as profiles
from serverware.operator_catalog_inputs import RevisionInput, _identifier
from serverware.operator_publication import exclusive, assert_held

TABLE = "operator_google_setups"
MAX_OPERATIONS = 1024
_PREFIX = "operator_catalog.google_setup."
_KEYS = {"operation_id", "actor_id", "client_id", "old_settings", "target_settings",
    "expected_settings_digest", "public_url", "redirect_uri", "profile_binding", "profile_binding_digest",
    "reviewed_revision", "staged_revision", "policy_hash", "created_at"}
_SQL = """CREATE TABLE operator_google_setups (
    operation_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, status TEXT NOT NULL,
    binding_json TEXT NOT NULL, terminal_revision INTEGER, terminal_policy_hash TEXT, completed_at TEXT) WITHOUT ROWID"""
_IMMUTABLE = """CREATE TRIGGER operator_google_setups_immutable BEFORE UPDATE ON operator_google_setups
    WHEN NEW.operation_id IS NOT OLD.operation_id OR NEW.actor_id IS NOT OLD.actor_id
      OR NEW.binding_json IS NOT OLD.binding_json OR OLD.status IS NOT 'pending'
      OR NEW.status NOT IN ('cancelled','activated')
    BEGIN SELECT RAISE(ABORT,'operator Google setup binding is immutable'); END"""
_RETAINED = """CREATE TRIGGER operator_google_setups_retained BEFORE DELETE ON operator_google_setups
    BEGIN SELECT RAISE(ABORT,'operator Google setup history must be retained'); END"""
_INSERT = """CREATE TRIGGER operator_google_setups_insert_guard BEFORE INSERT ON operator_google_setups
    WHEN EXISTS (SELECT 1 FROM operator_google_setups WHERE operation_id=NEW.operation_id)
      OR (NEW.status='pending' AND EXISTS (SELECT 1 FROM operator_google_setups WHERE status='pending'))
    BEGIN SELECT RAISE(ABORT,'operator Google setup already exists'); END"""
_PENDING = "CREATE UNIQUE INDEX operator_google_setups_one_pending ON operator_google_setups(status) WHERE status='pending'"
_DEFINITIONS = ((TABLE, "table", _SQL), (TABLE + "_immutable", "trigger", _IMMUTABLE),
    (TABLE + "_retained", "trigger", _RETAINED), (TABLE + "_insert_guard", "trigger", _INSERT),
    (TABLE + "_one_pending", "index", _PENDING))


class SetupUnavailable(RuntimeError):
    """Fixed, non-secret setup admission failure."""


class SetupNotFound(LookupError):
    """No operation belongs to this exact actor and locator."""


class SetupInput(RevisionInput):
    operation_id: str = Field(min_length=36, max_length=36)
    client_id: str = Field(min_length=1, max_length=240)
    expected_settings_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$", min_length=71, max_length=71)
    _uuid = field_validator("operation_id")(_identifier)

    @field_validator("client_id")
    @classmethod
    def google_client(cls, value):
        if profiles._CLIENT_ID.fullmatch(value) is None:
            raise ValueError("Google public client ID refused")
        return value


class CancelInput(RevisionInput):
    operation_id: str = Field(min_length=36, max_length=36)
    _uuid = field_validator("operation_id")(_identifier)


def _require(value):
    if not value:
        raise SetupUnavailable("operator Google setup unavailable")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _digest(value):
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _settings(raw):
    from serverware import operator_demo
    _require(isinstance(raw, str) and len(raw.encode("utf-8")) <= 16384)
    value = json.loads(raw)
    _require(isinstance(value, dict) and set(value) == {"allowed_upstreams", "fixture_cidrs"}
        and isinstance(value["allowed_upstreams"], list) and 1 <= len(value["allowed_upstreams"]) <= 16
        and all(isinstance(item, str) and operator_demo.origin(item)[0] == item for item in value["allowed_upstreams"])
        and len(set(value["allowed_upstreams"])) == len(value["allowed_upstreams"])
        and isinstance(value["fixture_cidrs"], list) and len(value["fixture_cidrs"]) <= 16
        and all(isinstance(item, str) for item in value["fixture_cidrs"])
        and raw == json.dumps(value, sort_keys=True))
    return value


def _target(old):
    origins = list(old["allowed_upstreams"])
    if "https://gmail.googleapis.com" not in origins:
        origins.append("https://gmail.googleapis.com")
    _require(len(origins) <= 16)
    return {"allowed_upstreams": origins, "fixture_cidrs": list(old["fixture_cidrs"])}


def _public_origin():
    from serverware import config, operator_demo
    origin, _ = operator_demo.origin(config.PUBLIC_URL)
    _require(config.PUBLIC_URL == origin and origin != "https://demo-upstream:8443")
    return origin, origin + profiles.CALLBACK_PATH


def _actor(actor_id):
    _require(isinstance(actor_id, str) and 1 <= len(actor_id) <= 512)


def _audit(conn, operation_id, action, expected):
    row = conn.execute("SELECT * FROM audit_events WHERE id=?", ("operator-google-setup:" + operation_id + ":" + action,)).fetchone()
    _require(row is not None and row["event_type"] == _PREFIX + action and row["actor_type"] == "admin"
        and row["actor_id"] == expected["actor_id"] and json.loads(row["event_json"]) == expected
        and row["event_hash"] == db._audit_hash(event_id=row["id"], event_type=row["event_type"],
            actor_type=row["actor_type"], actor_id=row["actor_id"], event_json=row["event_json"],
            prev_event_hash=row["prev_event_hash"], created_at=row["created_at"]))


def _terminal(item):
    return {"operation_id": item["operation_id"], "actor_id": item["actor_id"], "status": item["status"],
        "revision": item["terminal_revision"], "policy_hash": item["terminal_policy_hash"],
        "profile_binding_digest": item["binding"]["profile_binding_digest"], "completed_at": item["completed_at"]}


def _rows(conn):
    objects = {row["name"]: row for row in conn.execute("SELECT name,type,tbl_name,sql FROM sqlite_master "
        "WHERE name IN (" + ",".join("?" for _ in _DEFINITIONS) + ") OR (type='trigger' AND tbl_name=?)",
        (*[item[0] for item in _DEFINITIONS], TABLE))}
    audits = conn.execute("SELECT id FROM audit_events WHERE event_type IN (?,?,?) LIMIT ?",
        (*[_PREFIX + action for action in ("prepared", "cancelled", "activated")], 2 * MAX_OPERATIONS + 1)).fetchall()
    _require(len(audits) <= 2 * MAX_OPERATIONS)
    if not objects:
        _require(not audits)
        return []
    _require(set(objects) == {item[0] for item in _DEFINITIONS})
    for name, kind, sql in _DEFINITIONS:
        _require(objects[name]["type"] == kind and objects[name]["tbl_name"] == TABLE
            and " ".join(objects[name]["sql"].split()) == " ".join(sql.split()))
    records = conn.execute("SELECT * FROM " + TABLE + " ORDER BY operation_id LIMIT ?", (MAX_OPERATIONS + 1,)).fetchall()
    _require(len(records) <= MAX_OPERATIONS and {row["id"] for row in audits}
        == {"operator-google-setup:" + row["operation_id"] + ":" + action for row in records
            for action in (["prepared"] if row["status"] == "pending" else ["prepared", row["status"]])})
    result = []
    for row in records:
        _require(isinstance(row["binding_json"], str) and len(row["binding_json"].encode("utf-8")) <= 32768)
        binding = json.loads(row["binding_json"])
        _require(isinstance(binding, dict) and set(binding) == _KEYS and row["binding_json"] == _canonical(binding)
            and _identifier(row["operation_id"]) == binding["operation_id"] and row["actor_id"] == binding["actor_id"]
            and row["status"] in {"pending", "cancelled", "activated"}
            and profiles._CLIENT_ID.fullmatch(binding["client_id"]) is not None
            and binding["target_settings"] == _target(binding["old_settings"])
            and binding["expected_settings_digest"] == _digest(binding["old_settings"])
            and binding["profile_binding"] == profiles._record(binding["client_id"], binding["redirect_uri"])
            and binding["profile_binding_digest"] == _digest(binding["profile_binding"])
            and type(binding["reviewed_revision"]) is int and binding["reviewed_revision"] >= 1
            and binding["staged_revision"] == binding["reviewed_revision"] + 1
            and ((row["status"] == "pending" and row["terminal_revision"] is None
                    and row["terminal_policy_hash"] is None and row["completed_at"] is None)
                or (row["status"] != "pending" and type(row["terminal_revision"]) is int
                    and row["terminal_revision"] > binding["staged_revision"] and isinstance(row["completed_at"], str)
                    and isinstance(row["terminal_policy_hash"], str) and catalog._SHA.fullmatch(row["terminal_policy_hash"]))))
        item = {**dict(row), "binding": binding}
        _audit(conn, row["operation_id"], "prepared", binding)
        if row["status"] != "pending":
            _audit(conn, row["operation_id"], row["status"], _terminal(item))
        result.append(item)
    _require(sum(item["status"] == "pending" for item in result) <= 1)
    return result


def _public(item):
    binding = item["binding"]
    receipt = None
    if item["status"] == "activated":
        receipt = {"schema": "serverware.operatorGoogleSetupActivation/v1", "operation_id": item["operation_id"],
            "activated_revision": item["terminal_revision"], "policy_hash": binding["policy_hash"],
            "profile_binding_digest": binding["profile_binding_digest"],
            "settings_digest": _digest(binding["target_settings"]), "activated_at": item["completed_at"]}
    return {"schema": "serverware.operatorGoogleSetup/v1", **{key: value for key, value in binding.items() if key != "actor_id"},
        "status": item["status"], "revision": item["terminal_revision"] or binding["staged_revision"],
        "completed_at": item["completed_at"], "activation_receipt": receipt}


def _snapshot(conn, *, disabled):
    from serverware import operator_demo, operator_catalog_policy as policy
    _require(catalog.active(conn))
    if disabled:
        _require(not profiles.selected())
        catalog.validate_bindings(conn)
    _require(conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_catalog_oauth_profile'").fetchone() is None)
    value = catalog.read_catalog(conn)
    _require(not any(row.get("auth_type") == "google_oauth" for row in value["credentials"]))
    policy.verify_retained_policy(conn, value)
    row = conn.execute("SELECT settings_json FROM operator_demo_settings WHERE singleton=1").fetchone()
    _require(row is not None)
    old = _settings(row[0])
    if disabled:
        actual = operator_demo.settings()
        _require(old == {key: actual[key] for key in old})
    retained = dict(conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone())
    return value, retained, row[0], old


def review(actor_id):
    from serverware import operator_demo_store
    operator_demo_store._require()
    _actor(actor_id)
    with db.connect() as conn:
        conn.execute("BEGIN")
        value, policy, _, old = _snapshot(conn, disabled=True)
        rows = _rows(conn)
        origin, redirect = _public_origin()
        return {"schema": "serverware.operatorGoogleSetupReview/v1", "expected_revision": value["revision"],
            "expected_policy_hash": policy["policy_hash"], "expected_settings_digest": _digest(old),
            "old_settings": old, "target_settings": _target(old), "public_url": origin, "redirect_uri": redirect,
            "provider_id": "google", "permission_preset": profiles.PERMISSION_PRESET, "scopes": list(profiles.SCOPES),
            "eligible": not any(row["status"] == "pending" for row in rows) and len(rows) < MAX_OPERATIONS}


def _get(conn, operation_id, actor_id):
    _identifier(operation_id)
    _actor(actor_id)
    matches = [item for item in _rows(conn) if item["operation_id"] == operation_id and item["actor_id"] == actor_id]
    if not matches:
        raise SetupNotFound("operator Google setup not found")
    return matches[0]


def status(operation_id, actor_id):
    from serverware import operator_demo_store
    operator_demo_store._require()
    with db.connect() as conn:
        conn.execute("BEGIN")
        return _public(_get(conn, operation_id, actor_id))


def _append(conn, identifier, actor_id, action, event):
    db.append_audit_event(conn, event_type=_PREFIX + action, actor_type="admin", actor_id=actor_id,
        event=event, idempotency_key="operator-google-setup:" + identifier + ":" + action)


def prepare(payload, actor_id):
    from serverware import operator_demo_store
    operator_demo_store._require()
    payload = SetupInput.model_validate(payload.model_dump() if isinstance(payload, SetupInput) else payload)
    _actor(actor_id)
    with exclusive(), db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        value, policy, _, old = _snapshot(conn, disabled=True)
        if (value["revision"] != payload.expected_revision or policy["policy_hash"] != payload.expected_policy_hash
                or _digest(old) != payload.expected_settings_digest):
            raise catalog.CatalogConflict()
        rows = _rows(conn)
        if len(rows) >= MAX_OPERATIONS or any(item["status"] == "pending" or item["operation_id"] == payload.operation_id for item in rows):
            raise catalog.CatalogConflict()
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (TABLE,)).fetchone() is None:
            for _, _, sql in _DEFINITIONS:
                conn.execute(sql)
        origin, redirect = _public_origin()
        public_binding = profiles._record(payload.client_id, redirect)
        staged = catalog.advance_revision(conn, payload.expected_revision)
        binding = {"operation_id": payload.operation_id, "actor_id": actor_id, "client_id": payload.client_id,
            "old_settings": old, "target_settings": _target(old), "expected_settings_digest": _digest(old),
            "public_url": origin, "redirect_uri": redirect, "profile_binding": public_binding,
            "profile_binding_digest": _digest(public_binding), "reviewed_revision": payload.expected_revision,
            "staged_revision": staged, "policy_hash": policy["policy_hash"], "created_at": db.iso_now()}
        conn.execute("INSERT INTO " + TABLE + " VALUES (?,?,'pending',?,NULL,NULL,NULL)",
            (payload.operation_id, actor_id, _canonical(binding)))
        _append(conn, payload.operation_id, actor_id, "prepared", binding)
        result = _public(_get(conn, payload.operation_id, actor_id))
        conn.commit()
    return result


def cancel(payload, actor_id):
    from serverware import operator_demo_store
    operator_demo_store._require()
    payload = CancelInput.model_validate(payload.model_dump() if isinstance(payload, CancelInput) else payload)
    with exclusive(), db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        value, policy, _, _ = _snapshot(conn, disabled=True)
        item = _get(conn, payload.operation_id, actor_id)
        if (item["status"] != "pending" or value["revision"] != payload.expected_revision
                or policy["policy_hash"] != payload.expected_policy_hash):
            raise catalog.CatalogConflict()
        item.update(status="cancelled", terminal_revision=catalog.advance_revision(conn, payload.expected_revision),
            terminal_policy_hash=policy["policy_hash"], completed_at=db.iso_now())
        conn.execute("UPDATE " + TABLE + " SET status=?,terminal_revision=?,terminal_policy_hash=?,completed_at=? WHERE operation_id=?",
            (item["status"], item["terminal_revision"], item["terminal_policy_hash"], item["completed_at"], payload.operation_id))
        _append(conn, payload.operation_id, actor_id, "cancelled", _terminal(item))
        result = _public(_get(conn, payload.operation_id, actor_id))
        conn.commit()
    return result


def validate_startup(conn, previous_settings_raw, target_settings_raw, *, retained_authority=None):
    """Pure reads; preflight and the activation transaction use the same gates."""
    if not profiles.selected():
        return None
    if conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_catalog_oauth_profile'").fetchone():
        return None
    if not catalog.active(conn):
        if retained_authority is None:
            retained_authority = conn.execute("SELECT 1 FROM sqlite_master WHERE lower(name) GLOB 'operator_demo_*' "
                "OR lower(name) GLOB 'operator_catalog_*' OR lower(name) GLOB 'operator_google_*' LIMIT 1").fetchone() is not None
        _require(retained_authority is False and previous_settings_raw is None)
        return None
    _require(isinstance(conn, sqlite3.Connection) and previous_settings_raw is not None)
    value, policy, actual_raw, old = _snapshot(conn, disabled=False)
    target = _settings(target_settings_raw)
    rows = [item for item in _rows(conn) if item["status"] == "pending"]
    _require(len(rows) == 1)
    item, = rows
    binding = item["binding"]
    from serverware import config
    profile = profiles.validate_imported_configuration(config)
    origin, redirect = _public_origin()
    _require(actual_raw == previous_settings_raw and old == binding["old_settings"]
        and target == binding["target_settings"] == _target(old)
        and _digest(old) == binding["expected_settings_digest"]
        and value["revision"] == binding["staged_revision"] and policy["policy_hash"] == binding["policy_hash"]
        and origin == binding["public_url"] and redirect == binding["redirect_uri"] == profile.redirect_uri
        and profiles._record(profile.client_id, profile.redirect_uri) == binding["profile_binding"]
        and profile.binding_digest == binding["profile_binding_digest"])
    return item


def startup(conn, previous_settings_raw, target_settings_raw, *, retained_authority=None):
    assert_held()
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction)
    item = validate_startup(conn, previous_settings_raw, target_settings_raw, retained_authority=retained_authority)
    if item is None:
        return False
    from serverware import operator_catalog_policy as policy
    before = catalog.read_catalog(conn)
    retained = dict(conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone())
    conn.execute("UPDATE operator_demo_settings SET settings_json=? WHERE singleton=1", (target_settings_raw,))
    catalog.initialize(conn)
    catalog.validate_bindings(conn)
    policy.verify_retained_policy(conn, catalog.read_catalog(conn))
    _require(catalog.read_catalog(conn) == before
        and dict(conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone()) == retained)
    item.update(status="activated", terminal_revision=catalog.advance_revision(conn, item["binding"]["staged_revision"]),
        terminal_policy_hash=retained["policy_hash"], completed_at=db.iso_now())
    conn.execute("UPDATE " + TABLE + " SET status=?,terminal_revision=?,terminal_policy_hash=?,completed_at=? WHERE operation_id=?",
        (item["status"], item["terminal_revision"], item["terminal_policy_hash"], item["completed_at"], item["operation_id"]))
    _append(conn, item["operation_id"], item["actor_id"], "activated", _terminal(item))
    _require(_get(conn, item["operation_id"], item["actor_id"])["status"] == "activated")
    return True
