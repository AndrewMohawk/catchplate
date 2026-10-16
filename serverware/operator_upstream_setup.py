"""Reviewed public-origin changes, consumed only by an exact cold restart.

Preparation grants no requests and changes no process configuration. The
existing publication/SQLite owner atomically retains the operation and audit.
Credential custody, catalog resources, signed policy and fixture routing stay
unchanged. This is not provider, gate-readiness or production authority.
"""
from __future__ import annotations

from datetime import datetime
from functools import wraps
import hashlib
import ipaddress
import json
import sqlite3

from pydantic import Field, field_validator

from serverware import operator_catalog_schema as catalog
from serverware.db_common import audit_hash
from serverware.operator_catalog_inputs import RevisionInput, _identifier
from serverware.operator_demo import MAX_ALLOWED_UPSTREAMS
from serverware.operator_publication import assert_held, exclusive

TABLE = "operator_upstream_setups"
MAX_OPERATIONS = 1024
_PREFIX = "operator_catalog.upstream_setup."
_FIXTURE = "https://demo-upstream:8443"
_KEYS = {"operation_id", "actor_id", "old_settings", "target_settings", "expected_settings_digest",
    "target_settings_digest", "reviewed_revision", "staged_revision", "policy_hash", "signed_policy_digest",
    "profile_binding_digest", "public_url", "proxy_url", "created_at"}
_SQL = """CREATE TABLE operator_upstream_setups (
    operation_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, status TEXT NOT NULL,
    binding_json TEXT NOT NULL, terminal_revision INTEGER, terminal_policy_hash TEXT, completed_at TEXT) WITHOUT ROWID"""
_IMMUTABLE = """CREATE TRIGGER operator_upstream_setups_immutable BEFORE UPDATE ON operator_upstream_setups
    WHEN NEW.operation_id IS NOT OLD.operation_id OR NEW.actor_id IS NOT OLD.actor_id
      OR NEW.binding_json IS NOT OLD.binding_json OR OLD.status IS NOT 'pending'
      OR NEW.status NOT IN ('cancelled','activated')
    BEGIN SELECT RAISE(ABORT,'operator upstream setup binding is immutable'); END"""
_RETAINED = """CREATE TRIGGER operator_upstream_setups_retained BEFORE DELETE ON operator_upstream_setups
    BEGIN SELECT RAISE(ABORT,'operator upstream setup history must be retained'); END"""
_INSERT = """CREATE TRIGGER operator_upstream_setups_insert_guard BEFORE INSERT ON operator_upstream_setups
    WHEN EXISTS (SELECT 1 FROM operator_upstream_setups WHERE operation_id=NEW.operation_id)
      OR (NEW.status='pending' AND EXISTS (SELECT 1 FROM operator_upstream_setups WHERE status='pending'))
    BEGIN SELECT RAISE(ABORT,'operator upstream setup already exists'); END"""
_PENDING = "CREATE UNIQUE INDEX operator_upstream_setups_one_pending ON operator_upstream_setups(status) WHERE status='pending'"
_DEFINITIONS = ((TABLE, "table", _SQL), (TABLE + "_immutable", "trigger", _IMMUTABLE),
    (TABLE + "_retained", "trigger", _RETAINED), (TABLE + "_insert_guard", "trigger", _INSERT),
    (TABLE + "_one_pending", "index", _PENDING))


class SetupUnavailable(RuntimeError):
    """Fixed failure; it does not prove a mutation was rolled back."""


class SetupNotFound(LookupError):
    """No retained operation belongs to this actor and exact locator."""


class SetupRejected(ValueError):
    """A fixed semantic target rejection before any mutation writes."""


def _require(condition):
    if not condition:
        raise SetupUnavailable("operator upstream setup unavailable")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _digest(value):
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _origins(values):
    from serverware.operator_demo import origin
    if (not isinstance(values, list) or not 1 <= len(values) <= MAX_ALLOWED_UPSTREAMS
            or any(not isinstance(value, str) or origin(value)[0] != value for value in values)
            or len(set(values)) != len(values)):
        raise ValueError("canonical unique HTTPS origins required")
    return list(values)


class PrepareInput(RevisionInput):
    operation_id: str = Field(min_length=36, max_length=36)
    allowed_upstreams: list[str] = Field(min_length=1, max_length=MAX_ALLOWED_UPSTREAMS)
    expected_settings_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$", min_length=71, max_length=71)
    _uuid = field_validator("operation_id")(_identifier)
    _canonical_origins = field_validator("allowed_upstreams")(_origins)


class CancelInput(RevisionInput):
    operation_id: str = Field(min_length=36, max_length=36)
    _uuid = field_validator("operation_id")(_identifier)


def _settings(raw):
    _require(isinstance(raw, str) and len(raw.encode("utf-8")) <= 16384)
    value = json.loads(raw)
    _require(isinstance(value, dict) and set(value) == {"allowed_upstreams", "fixture_cidrs"}
        and _origins(value["allowed_upstreams"]) == value["allowed_upstreams"]
        and isinstance(value["fixture_cidrs"], list) and len(value["fixture_cidrs"]) <= 1
        and bool(value["fixture_cidrs"]) == (_FIXTURE in value["allowed_upstreams"])
        and raw == json.dumps(value, sort_keys=True))
    private = tuple(ipaddress.ip_network(item) for item in
        ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"))
    for cidr in value["fixture_cidrs"]:
        _require(isinstance(cidr, str))
        network = ipaddress.ip_network(cidr, strict=True)
        _require(str(network) == cidr and network.prefixlen == network.max_prefixlen
            and any(network.version == item.version and network.network_address in item for item in private))
    return value


def _actor(actor):
    _require(isinstance(actor, str) and 1 <= len(actor) <= 512
        and all(ord(char) >= 32 and ord(char) != 127 for char in actor))


def _timestamp(value):
    _require(isinstance(value, str) and value.isascii() and 1 <= len(value) <= 128
        and datetime.fromisoformat(value).tzinfo is not None)


def _audit(conn, operation_id, action, expected):
    row = conn.execute("SELECT * FROM audit_events WHERE id=?",
        ("operator-upstream-setup:" + operation_id + ":" + action,)).fetchone()
    _require(row is not None and row["event_type"] == _PREFIX + action and row["actor_type"] == "admin"
        and row["actor_id"] == expected["actor_id"] and json.loads(row["event_json"]) == expected
        and row["event_hash"] == audit_hash(event_id=row["id"], event_type=row["event_type"],
            actor_type=row["actor_type"], actor_id=row["actor_id"], event_json=row["event_json"],
            prev_event_hash=row["prev_event_hash"], created_at=row["created_at"]))


def _terminal(item):
    return {"operation_id": item["operation_id"], "actor_id": item["actor_id"], "status": item["status"],
        "revision": item["terminal_revision"], "policy_hash": item["terminal_policy_hash"],
        "settings_digest": item["binding"]["target_settings_digest"], "completed_at": item["completed_at"]}


def _rows(conn):
    """Exact retained schema and immutable audit joins; never repair history."""
    try:
        return _decode_rows(conn)
    except (sqlite3.Error, ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
        raise SetupUnavailable("operator upstream setup unavailable") from None


def _decode_rows(conn):
    objects = {row["name"]: row for row in conn.execute("SELECT name,type,tbl_name,sql FROM sqlite_master "
        "WHERE lower(name) GLOB 'operator_upstream_*' OR lower(tbl_name) GLOB 'operator_upstream_*'")}
    audits = conn.execute("SELECT id FROM audit_events WHERE event_type LIKE ? LIMIT ?",
        (_PREFIX + "%", 2 * MAX_OPERATIONS + 1)).fetchall()
    _require(len(audits) <= 2 * MAX_OPERATIONS)
    if not objects:
        _require(not audits)
        return []
    _require(set(objects) == {definition[0] for definition in _DEFINITIONS})
    for name, kind, sql in _DEFINITIONS:
        _require(objects[name]["type"] == kind and objects[name]["tbl_name"] == TABLE
            and " ".join(objects[name]["sql"].split()) == " ".join(sql.split()))
    rows = conn.execute("SELECT * FROM " + TABLE + " ORDER BY operation_id LIMIT ?", (MAX_OPERATIONS + 1,)).fetchall()
    _require(len(rows) <= MAX_OPERATIONS and {row["id"] for row in audits}
        == {"operator-upstream-setup:" + row["operation_id"] + ":" + action for row in rows
            for action in (["prepared"] if row["status"] == "pending" else ["prepared", row["status"]])})
    result = []
    for row in rows:
        _require(isinstance(row["binding_json"], str) and len(row["binding_json"].encode("utf-8")) <= 32768)
        binding = json.loads(row["binding_json"])
        _require(isinstance(binding, dict) and set(binding) == _KEYS and row["binding_json"] == _canonical(binding)
            and _identifier(row["operation_id"]) == binding["operation_id"] and row["actor_id"] == binding["actor_id"]
            and row["status"] in {"pending", "cancelled", "activated"})
        _actor(binding["actor_id"])
        _timestamp(binding["created_at"])
        old, target = (_settings(json.dumps(binding[key], sort_keys=True)) for key in ("old_settings", "target_settings"))
        _require(old["fixture_cidrs"] == target["fixture_cidrs"]
            and (_FIXTURE in old["allowed_upstreams"]) == (_FIXTURE in target["allowed_upstreams"])
            and set(old["allowed_upstreams"]) != set(target["allowed_upstreams"])
            and binding["expected_settings_digest"] == _digest(old)
            and binding["target_settings_digest"] == _digest(target)
            and type(binding["reviewed_revision"]) is int and 1 <= binding["reviewed_revision"] < 9_007_199_254_740_989
            and type(binding["staged_revision"]) is int and binding["staged_revision"] == binding["reviewed_revision"] + 1
            and all(isinstance(binding[key], str) and catalog._SHA.fullmatch(binding[key])
                for key in ("policy_hash", "signed_policy_digest"))
            and (binding["profile_binding_digest"] is None or isinstance(binding["profile_binding_digest"], str)
                and catalog._SHA.fullmatch(binding["profile_binding_digest"]))
            and all(isinstance(binding[key], str) and 1 <= len(binding[key]) <= 2048 for key in ("public_url", "proxy_url")))
        if row["status"] == "pending":
            _require(all(row[key] is None for key in ("terminal_revision", "terminal_policy_hash", "completed_at")))
        else:
            _require(type(row["terminal_revision"]) is int and binding["staged_revision"] < row["terminal_revision"] < 9_007_199_254_740_991
                and isinstance(row["terminal_policy_hash"], str) and catalog._SHA.fullmatch(row["terminal_policy_hash"]))
            _timestamp(row["completed_at"])
            if row["status"] == "activated":
                _require(row["terminal_revision"] == binding["staged_revision"] + 1
                    and row["terminal_policy_hash"] == binding["policy_hash"])
        item = {**dict(row), "binding": binding}
        _audit(conn, row["operation_id"], "prepared", binding)
        if row["status"] != "pending":
            _audit(conn, row["operation_id"], row["status"], _terminal(item))
        result.append(item)
    _require(sum(item["status"] == "pending" for item in result) <= 1)
    return result


def pending(conn):
    """Read-only mutual-exclusion join for the existing Google setup owner."""
    return any(item["status"] == "pending" for item in _rows(conn))


def _google_pending(conn):
    from serverware import operator_google_setup
    return any(item["status"] == "pending" for item in operator_google_setup._rows(conn))


def _snapshot(conn, *, effective, metadata_profile=None):
    from serverware import config, operator_demo, operator_catalog_google, operator_catalog_policy as policy
    if metadata_profile is not None:
        from serverware import operator_google_managed_config, operator_catalog_oauth_profile
        # This alternate input is public metadata confined to the real cold
        # read snapshot. It never makes require_profile available to requests.
        _require(effective is False and isinstance(conn, sqlite3.Connection) and conn.in_transaction
            and conn.execute("PRAGMA query_only").fetchone()[0] == 1)
        operation = operator_google_managed_config.validate_selection(conn)
        _require(operation is not None and operation["status"] == "activated"
            and metadata_profile == operator_catalog_oauth_profile.validate_imported_configuration(config))
    _require(catalog.active(conn))
    value = catalog.read_catalog(conn)
    catalog.validate_bindings(conn, value, metadata_profile=metadata_profile)
    policy.verify_retained_policy(conn, value, metadata_profile=metadata_profile)
    retained, signed = policy._retained(conn)
    row = conn.execute("SELECT settings_json FROM operator_demo_settings WHERE singleton=1").fetchone()
    _require(row is not None)
    old = _settings(row[0])
    actual = operator_demo.settings()
    if effective:
        _require(old == {key: actual[key] for key in old})
    profile = operator_catalog_google.validate_profile_binding(conn, metadata_profile=metadata_profile)
    return {"catalog": value, "policy": dict(retained), "signed": signed, "raw": row[0], "old": old,
        "profile_binding_digest": profile.binding_digest if profile else None,
        "public_url": config.PUBLIC_URL, "proxy_url": actual["proxy_url"]}


def _protected(snapshot):
    from serverware.operator_demo import origin
    reasons = {}
    def protect(value, reason):
        reasons.setdefault(value, set()).add(reason)
    if _FIXTURE in snapshot["old"]["allowed_upstreams"]:
        protect(_FIXTURE, "fixture")
    for rule in snapshot["catalog"]["access_rules"]:
        if rule["status"] == "active":
            protect(origin(rule["upstream_url"], target=True)[0], "active_rule")
    fixed_first = None
    for route in snapshot["signed"]["routes"]:
        match = route["match"]
        value = "https://" + match["host"] + (":" + str(match["port"]) if match["port"] != 443 else "")
        _require(origin(value)[0] == value)
        protect(value, "retained_policy")
        if route["id"] == "operator.empty":
            fixed_first = value
    if snapshot["profile_binding_digest"] is not None:
        protect("https://gmail.googleapis.com", "google_profile")
    return [{"origin": value, "reasons": sorted(selected)} for value, selected in sorted(reasons.items())], fixed_first


def _target(snapshot, origins):
    old = snapshot["old"]
    if set(origins) == set(old["allowed_upstreams"]):
        raise SetupRejected("upstream changes require an added or removed origin")
    if (_FIXTURE in origins) != (_FIXTURE in old["allowed_upstreams"]):
        raise SetupRejected("fixture origin and routing must remain unchanged")
    protected, first = _protected(snapshot)
    if any(item["origin"] not in origins for item in protected):
        raise SetupRejected("an origin used by retained authority cannot be removed")
    if first is not None and origins[0] != first:
        raise SetupRejected("the retained empty policy origin must remain first")
    return {"allowed_upstreams": list(origins), "fixture_cidrs": list(old["fixture_cidrs"])}


def _public(item):
    binding = item["binding"]
    receipt = None
    if item["status"] == "activated":
        receipt = {"schema": "serverware.operatorUpstreamSetupActivation/v1", "operation_id": item["operation_id"],
            "activated_revision": item["terminal_revision"], "policy_hash": binding["policy_hash"],
            "settings_digest": binding["target_settings_digest"], "activated_at": item["completed_at"]}
    return {"schema": "serverware.operatorUpstreamSetup/v1",
        **{key: binding[key] for key in ("operation_id", "old_settings", "target_settings", "expected_settings_digest",
            "target_settings_digest", "reviewed_revision", "staged_revision", "policy_hash", "created_at")},
        "status": item["status"], "revision": item["terminal_revision"] or binding["staged_revision"],
        "completed_at": item["completed_at"], "activation_receipt": receipt}


def _get(conn, operation_id, actor):
    _identifier(operation_id)
    _actor(actor)
    matches = [item for item in _rows(conn) if item["operation_id"] == operation_id and item["actor_id"] == actor]
    if not matches:
        raise SetupNotFound("operator upstream setup not found")
    return matches[0]


def _storage(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (SetupNotFound, catalog.CatalogConflict, SetupRejected):
            raise
        except Exception:
            raise SetupUnavailable("operator upstream setup unavailable") from None
    return wrapped


@_storage
def review(actor):
    from serverware import operator_demo_store
    db = operator_demo_store._require()
    _actor(actor)
    with db.connect() as conn:
        conn.execute("BEGIN")
        snapshot = _snapshot(conn, effective=True)
        rows = _rows(conn)
        current = next((item for item in rows if item["status"] == "pending"), None)
        reason = "pending_operation" if current else "pending_google_setup" if _google_pending(conn) else "capacity" if len(rows) >= MAX_OPERATIONS else None
        protected, first = _protected(snapshot)
        return {"schema": "serverware.operatorUpstreamSetupReview/v1", "expected_revision": snapshot["catalog"]["revision"],
            "expected_policy_hash": snapshot["policy"]["policy_hash"], "expected_settings_digest": _digest(snapshot["old"]),
            "old_settings": snapshot["old"], "protected_origins": protected, "fixed_first_origin": first,
            "eligible": reason is None, "pending_operation_id": current["operation_id"] if current and current["actor_id"] == actor else None,
            "blocked_reason": reason, "cold_restart_required": True}


@_storage
def status(operation_id, actor):
    from serverware import operator_demo_store
    db = operator_demo_store._require()
    with db.connect() as conn:
        conn.execute("BEGIN")
        return _public(_get(conn, operation_id, actor))


def _append(conn, item, action, event):
    from serverware import db
    db.append_audit_event(conn, event_type=_PREFIX + action, actor_type="admin", actor_id=item["actor_id"],
        event=event, idempotency_key="operator-upstream-setup:" + item["operation_id"] + ":" + action)


def prepare(payload, actor):
    # The only ValueErrors exposed to the API are definite precommit inputs.
    payload = PrepareInput.model_validate(payload.model_dump() if isinstance(payload, PrepareInput) else payload)
    return _prepare(payload, actor)


@_storage
def _prepare(payload, actor):
    from serverware import operator_demo_store
    db = operator_demo_store._require()
    _actor(actor)
    with exclusive(), db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        snapshot = _snapshot(conn, effective=True)
        if (snapshot["catalog"]["revision"] != payload.expected_revision
                or snapshot["policy"]["policy_hash"] != payload.expected_policy_hash
                or _digest(snapshot["old"]) != payload.expected_settings_digest):
            raise catalog.CatalogConflict()
        rows = _rows(conn)
        if len(rows) >= MAX_OPERATIONS or any(item["status"] == "pending" or item["operation_id"] == payload.operation_id for item in rows) or _google_pending(conn):
            raise catalog.CatalogConflict()
        target = _target(snapshot, payload.allowed_upstreams)
        try:
            if not rows and conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (TABLE,)).fetchone() is None:
                for _, _, sql in _DEFINITIONS:
                    conn.execute(sql)
            staged = catalog.advance_revision(conn, payload.expected_revision)
            binding = {"operation_id": payload.operation_id, "actor_id": actor, "old_settings": snapshot["old"],
                "target_settings": target, "expected_settings_digest": _digest(snapshot["old"]), "target_settings_digest": _digest(target),
                "reviewed_revision": payload.expected_revision, "staged_revision": staged,
                "policy_hash": snapshot["policy"]["policy_hash"], "signed_policy_digest": _digest(snapshot["policy"]["signed_bundle_json"]),
                "profile_binding_digest": snapshot["profile_binding_digest"], "public_url": snapshot["public_url"],
                "proxy_url": snapshot["proxy_url"], "created_at": db.iso_now()}
            conn.execute("INSERT INTO " + TABLE + " VALUES (?,?,'pending',?,NULL,NULL,NULL)",
                (payload.operation_id, actor, _canonical(binding)))
            _append(conn, binding, "prepared", binding)
            result = _public(_get(conn, payload.operation_id, actor))
            conn.commit()
        except catalog.CatalogConflict:
            raise
        except Exception:
            raise SetupUnavailable("operator upstream setup unavailable") from None
    return result


def cancel(payload, actor):
    payload = CancelInput.model_validate(payload.model_dump() if isinstance(payload, CancelInput) else payload)
    return _cancel(payload, actor)


@_storage
def _cancel(payload, actor):
    from serverware import operator_demo_store
    db = operator_demo_store._require()
    with exclusive(), db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        snapshot = _snapshot(conn, effective=True)
        item = _get(conn, payload.operation_id, actor)
        if (item["status"] != "pending" or snapshot["catalog"]["revision"] != payload.expected_revision
                or snapshot["policy"]["policy_hash"] != payload.expected_policy_hash):
            raise catalog.CatalogConflict()
        try:
            item.update(status="cancelled", terminal_revision=catalog.advance_revision(conn, payload.expected_revision),
                terminal_policy_hash=snapshot["policy"]["policy_hash"], completed_at=db.iso_now())
            _complete(conn, item)
            result = _public(_get(conn, payload.operation_id, actor))
            conn.commit()
        except catalog.CatalogConflict:
            raise
        except Exception:
            raise SetupUnavailable("operator upstream setup unavailable") from None
    return result


def _complete(conn, item):
    _require(conn.execute("UPDATE " + TABLE + " SET status=?,terminal_revision=?,terminal_policy_hash=?,completed_at=? "
        "WHERE operation_id=? AND status='pending'", (item["status"], item["terminal_revision"], item["terminal_policy_hash"],
            item["completed_at"], item["operation_id"])).rowcount == 1)
    _append(conn, item, item["status"], _terminal(item))


@_storage
def validate_startup(conn, previous_settings_raw, target_settings_raw, *, retained_authority=None, metadata_profile=None):
    """Read-only exact gate, repeated under the cold writer before consume."""
    rows = _rows(conn)
    if previous_settings_raw is None:
        _require(not rows and conn.execute("SELECT 1 FROM sqlite_master WHERE lower(name) GLOB 'operator_upstream_*' "
            "OR lower(tbl_name) GLOB 'operator_upstream_*' LIMIT 1").fetchone() is None)
        return None
    old, target = _settings(previous_settings_raw), _settings(target_settings_raw)
    if previous_settings_raw == target_settings_raw:
        return None
    current = [item for item in rows if item["status"] == "pending"]
    if not current:
        # Preserve the separately reviewed existing first-Google transition.
        from serverware import operator_google_setup
        _require(operator_google_setup.validate_startup(conn, previous_settings_raw, target_settings_raw,
            retained_authority=retained_authority) is not None)
        return None
    _require(len(current) == 1 and not _google_pending(conn))
    item = current[0]
    binding = item["binding"]
    snapshot = _snapshot(conn, effective=False, metadata_profile=metadata_profile)
    _require(snapshot["raw"] == previous_settings_raw and old == binding["old_settings"]
        and target == binding["target_settings"] and target == _target(snapshot, target["allowed_upstreams"])
        and snapshot["catalog"]["revision"] == binding["staged_revision"]
        and snapshot["policy"]["policy_hash"] == binding["policy_hash"]
        and _digest(snapshot["policy"]["signed_bundle_json"]) == binding["signed_policy_digest"]
        and snapshot["profile_binding_digest"] == binding["profile_binding_digest"]
        and snapshot["public_url"] == binding["public_url"] and snapshot["proxy_url"] == binding["proxy_url"])
    return item


@_storage
def startup(conn, previous_settings_raw, target_settings_raw, *, retained_authority=None):
    from serverware import db
    assert_held()
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction)
    item = validate_startup(conn, previous_settings_raw, target_settings_raw, retained_authority=retained_authority)
    if item is None:
        return False
    before = catalog.read_catalog(conn)
    retained = dict(conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone())
    _require(conn.execute("UPDATE operator_demo_settings SET settings_json=? WHERE singleton=1 AND settings_json=?",
        (target_settings_raw, previous_settings_raw)).rowcount == 1)
    catalog.validate_bindings(conn)
    from serverware import operator_catalog_policy as policy
    policy.verify_retained_policy(conn, catalog.read_catalog(conn))
    _require(catalog.read_catalog(conn) == before
        and dict(conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone()) == retained)
    item.update(status="activated", terminal_revision=catalog.advance_revision(conn, item["binding"]["staged_revision"]),
        terminal_policy_hash=retained["policy_hash"], completed_at=db.iso_now())
    _complete(conn, item)
    _require(_get(conn, item["operation_id"], item["actor_id"])["status"] == "activated")
    return True
