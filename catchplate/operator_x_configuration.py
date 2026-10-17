"""First-save X application configuration under the ordinary publication owner.

One transaction retains the original public binding, encrypted client secret,
audit event and catalog revision. Discovery opens only existing read-only state;
it neither initializes custody nor authorizes consent, accounts, grants or
provider contact. Replacement and disable are deliberately not implemented.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from datetime import datetime
import json
import sqlite3
import uuid

from catchplate import operator_catalog_schema as catalog
from catchplate import operator_x_admission as admission
from catchplate import operator_x_oauth_profile as profiles
from catchplate import operator_x_provider_custody as custody
from catchplate import operator_provider_key as keys
from catchplate.db_common import audit_hash

SCHEMA = "catchplate.operatorXConfiguration/v1"
OPERATION_SCHEMA = "catchplate.operatorXConfigurationOperation/v1"
TABLE = "operator_x_configuration"
EVENT = "operator_catalog.x_oauth.configuration_saved"
_AUDIT_PREFIX = "operator-x-configuration:"
_BINDING_SCHEMA = "catchplate.operatorXConfigurationBinding/v1"
_ERROR = "operator X configuration unavailable"
_FIELDS = {"schema", "operation_id", "actor_id", "owner_id", "config_version",
    "public_profile", "profile_binding_digest", "reviewed_revision", "committed_revision",
    "policy_hash", "created_at"}
_SQL = """CREATE TABLE operator_x_configuration (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), operation_id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL, binding_json TEXT NOT NULL)"""
_IMMUTABLE = """CREATE TRIGGER operator_x_configuration_immutable BEFORE UPDATE ON operator_x_configuration
    BEGIN SELECT RAISE(ABORT,'operator X configuration is immutable'); END"""
_RETAINED = """CREATE TRIGGER operator_x_configuration_retained BEFORE DELETE ON operator_x_configuration
    BEGIN SELECT RAISE(ABORT,'operator X configuration must be retained'); END"""
_INSERT = """CREATE TRIGGER operator_x_configuration_insert_guard BEFORE INSERT ON operator_x_configuration
    WHEN EXISTS (SELECT 1 FROM operator_x_configuration)
    BEGIN SELECT RAISE(ABORT,'operator X configuration already exists'); END"""
_DEFINITIONS = ((TABLE, "table", _SQL),
    (TABLE + "_immutable", "trigger", _IMMUTABLE),
    (TABLE + "_retained", "trigger", _RETAINED),
    (TABLE + "_insert_guard", "trigger", _INSERT))


class ConfigurationUnavailable(RuntimeError):
    """Fixed failure; after POST it is not evidence that a commit did not occur."""


class ConfigurationNotFound(LookupError):
    """No exact retained operation belongs to this actor."""


def _require(condition):
    if not condition:
        raise ConfigurationUnavailable(_ERROR)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _identifier(value):
    _require(type(value) is str and len(value) == 36 and str(uuid.UUID(value)) == value)
    return value


def _actor(value):
    _require(type(value) is str and 1 <= len(value) <= 512
        and all(ord(char) >= 32 and ord(char) != 127 for char in value))


def _timestamp(value):
    _require(type(value) is str and value.isascii() and 1 <= len(value) <= 128
        and datetime.fromisoformat(value).tzinfo is not None)


def _objects(conn, prefix):
    # No temp shadowing and no similarly named extra objects in this namespace.
    # Inspect an existing temp schema only. Reading sqlite_temp_master creates
    # an empty one, which would mutate this borrowed connection's namespace
    # during catalog validation and break the main-only startup owner.
    if any(row[1] == "temp" for row in conn.execute("PRAGMA database_list")):
        _require(conn.execute("SELECT 1 FROM sqlite_temp_master LIMIT 1").fetchone() is None)
    rows = conn.execute("SELECT name,type,tbl_name,sql FROM main.sqlite_master "
        "WHERE lower(name) GLOB ? OR lower(tbl_name) GLOB ? LIMIT 17",
        (prefix + "*", prefix + "*")).fetchall()
    _require(len(rows) <= 16)
    return {row["name"]: row for row in rows}


def _audit_body(binding):
    return {key: binding[key] for key in ("operation_id", "actor_id", "config_version",
        "reviewed_revision", "committed_revision", "policy_hash", "profile_binding_digest", "created_at")}


def retained_public_binding(conn):
    """Original public row/audit binding under the caller's transaction.

    This does not decrypt material, acquire publication locks, inspect the
    catalog, or authorize provider contact. It is safe for catalog validators
    already running inside the actual metadata owner.
    """
    objects = _objects(conn, TABLE)
    audits = conn.execute("SELECT id FROM main.audit_events WHERE event_type=? "
        "OR lower(id) GLOB ? LIMIT 2", (EVENT, _AUDIT_PREFIX + "*")).fetchall()
    if not objects:
        _require(not audits and not _objects(conn, custody.TABLE))
        return None
    # SQLite's automatically generated UNIQUE index has no stored SQL.
    index = "sqlite_autoindex_" + TABLE + "_1"
    expected = {name for name, _, _ in _DEFINITIONS} | {index}
    _require(set(objects) == expected)
    for name, kind, sql in _DEFINITIONS:
        found = objects[name]
        _require(found["type"] == kind and found["tbl_name"] == TABLE
            and type(found["sql"]) is str and " ".join(found["sql"].split()) == " ".join(sql.split()))
    _require(objects[index]["type"] == "index" and objects[index]["tbl_name"] == TABLE
        and objects[index]["sql"] is None)
    sizes = conn.execute("SELECT typeof(binding_json),length(CAST(binding_json AS BLOB)) "
        "FROM main.operator_x_configuration LIMIT 2").fetchall()
    _require(len(sizes) == 1 and sizes[0][0] == "text" and 1 <= sizes[0][1] <= 16384)
    row = conn.execute("SELECT * FROM main.operator_x_configuration").fetchone()
    binding = json.loads(row["binding_json"])
    _require(type(binding) is dict and set(binding) == _FIELDS
        and row["binding_json"] == _canonical(binding) and row["singleton"] == 1
        and binding["schema"] == _BINDING_SCHEMA
        and _identifier(row["operation_id"]) == binding["operation_id"]
        and row["actor_id"] == binding["actor_id"])
    _actor(binding["actor_id"])
    _timestamp(binding["created_at"])
    _identifier(binding["owner_id"])
    profile = profiles.parse_profile(binding["public_profile"])
    _require(profile.redirect_uri == admission.public_origin() + profiles.CALLBACK_PATH
        and binding["profile_binding_digest"] == profile.binding_digest
        and type(binding["config_version"]) is int and binding["config_version"] == 1
        and type(binding["reviewed_revision"]) is int
        and 1 <= binding["reviewed_revision"] < 9_007_199_254_740_990
        and type(binding["committed_revision"]) is int
        and binding["committed_revision"] == binding["reviewed_revision"] + 1
        and type(binding["policy_hash"]) is str and catalog._SHA.fullmatch(binding["policy_hash"]))
    event_id = _AUDIT_PREFIX + binding["operation_id"]
    _require(len(audits) == 1 and audits[0]["id"] == event_id)
    event = conn.execute("SELECT * FROM main.audit_events WHERE id=?", (event_id,)).fetchone()
    _require(event["event_type"] == EVENT and event["actor_type"] == "admin"
        and event["actor_id"] == binding["actor_id"]
        and type(event["event_json"]) is str and len(event["event_json"].encode("utf-8")) <= 16384
        and event["event_json"] == _canonical(_audit_body(binding))
        and event["event_hash"] == audit_hash(event_id=event_id, event_type=EVENT,
            actor_type="admin", actor_id=event["actor_id"], event_json=event["event_json"],
            prev_event_hash=event["prev_event_hash"], created_at=event["created_at"]))
    return binding


def _record(conn, directory):
    """Exact row/audit/custody bijection, including authenticated key readback."""
    binding = retained_public_binding(conn)
    if binding is None:
        return None
    owner = admission.admit_owner(binding["owner_id"])
    bound = custody.bind_x(owner, config_version=1, public_profile=binding["public_profile"])
    _require(custody.inspect_public_roster(conn, owner) == ({"schema": custody.SCHEMA,
        "owner_id": owner.owner_id, "config_version": 1,
        "public_profile": binding["public_profile"], "secret_present": True},))
    pin = keys.read_existing_pinned(directory, owner.owner_id)
    try:
        # This is an exact existing-key read, never initialization or a latest-key fallback.
        material = custody.read_secret(conn, owner, bound, key=pin.material)
        profiles.validate_client_secret(material.secret)
        keys.check_pin(pin)
    finally:
        keys.close_pin(pin)
    return binding


@dataclass(frozen=True)
class _RetainedSelection:
    """Private existing material, not consent, dispatch or mutation authority."""
    record: dict = field(repr=False)
    profile: profiles.Profile = field(repr=False)
    client_secret: str = field(repr=False)
    key_pin: keys.KeyAdmission = field(repr=False)


@contextmanager
def _retained_selection(conn, directory):
    """Select the immutable configured client; never initialize or fall back.

    Enter only inside the caller's admitted database transaction. The caller
    may close that transaction before provider I/O while this context retains
    the exact key descriptor. Recheck the pin before each effect; this context
    also rechecks and closes it on exit. Public callers must not serialize the
    returned selection or its private material.
    """
    pin = None
    try:
        admission.check_connection(conn, directory)
        record = _record(conn, directory)
        _require(record is not None)
        profile = profiles.parse_profile(record["public_profile"])
        owner = admission.admit_owner(record["owner_id"])
        bound = custody.bind_x(owner, config_version=record["config_version"],
            public_profile=record["public_profile"])
        pin = keys.read_existing_pinned(directory, owner.owner_id)
        private = custody.read_secret(conn, owner, bound, key=pin.material)
        profiles.validate_client_secret(private.secret)
        keys.check_pin(pin)
        admission.check_connection(conn, directory)
        yield _RetainedSelection(json.loads(_canonical(record)), profile, private.secret, pin)
    finally:
        if pin is not None:
            try:
                keys.check_pin(pin)
            finally:
                keys.close_pin(pin)


def _snapshot(conn, directory):
    from catchplate import operator_catalog_policy as policy
    from catchplate import operator_google_setup as google, operator_upstream_setup as upstream
    admission.check_connection(conn, directory)
    _require(catalog.active(conn))
    resources = catalog.read_catalog(conn)
    catalog.validate_bindings(conn, resources)
    policy.verify_retained_policy(conn, resources)
    retained, _ = policy._retained(conn)
    record = _record(conn, directory)
    if record is not None:
        _require(record["committed_revision"] <= resources["revision"])
    google_pending = any(row["status"] == "pending" for row in google._rows(conn))
    upstream_pending = upstream.pending(conn)
    blocked = ("already_configured" if record is not None else
        "pending_google_configuration" if google_pending else
        "pending_upstream_configuration" if upstream_pending else None)
    admission.check_connection(conn, directory)
    return resources, dict(retained), record, blocked


def _public_configuration(record):
    return {"config_version": 1, "profile_binding_digest": record["profile_binding_digest"],
        "public_profile": record["public_profile"], "client_secret_configured": True}


def _operation(record):
    return {"schema": OPERATION_SCHEMA, "operation_id": record["operation_id"],
        "status": "committed", "committed_revision": record["committed_revision"],
        "policy_hash": record["policy_hash"], **_public_configuration(record), "consent_ready": False}


def _discover(value, actor_id):
    resources, policy, record, blocked = value
    return {"schema": SCHEMA, "state": "unconfigured" if record is None else "configured",
        "revision": resources["revision"], "policy_hash": policy["policy_hash"],
        "redirect_uri": admission.public_origin() + profiles.CALLBACK_PATH,
        "permission_preset": profiles.PERMISSION_PRESET, "scopes": list(profiles.SCOPES),
        "configuration": None if record is None else _public_configuration(record),
        "operation": _operation(record) if record is not None and record["actor_id"] == actor_id else None,
        "review": {"expected_revision": resources["revision"], "expected_policy_hash": policy["policy_hash"]}
            if blocked is None else None,
        "blocked_reason": blocked, "consent_ready": False}


def _read(actor_id):
    from catchplate import operator_publication as publication
    from catchplate.development_sandbox import _open_directory
    _actor(actor_id)
    directory = admission.require_runtime()
    publication.assert_not_held()
    with publication.exclusive():
        with publication.closing_fd(_open_directory(publication._directory())) as descriptor:
            with publication._read_database(descriptor) as conn:
                return _snapshot(conn, directory)


def configuration(actor_id):
    """Public discovery from one real read-only snapshot; no hidden setup."""
    try:
        return _discover(_read(actor_id), actor_id)
    except Exception:
        raise ConfigurationUnavailable(_ERROR) from None


def status(operation_id, actor_id):
    """Recover a committed first save for its original actor, never retry it."""
    try:
        _identifier(operation_id)
        _, _, record, _ = _read(actor_id)
        if record is None or record["actor_id"] != actor_id or record["operation_id"] != operation_id:
            raise ConfigurationNotFound("operator X configuration operation not found")
        return _operation(record)
    except ConfigurationNotFound:
        raise
    except Exception:
        raise ConfigurationUnavailable(_ERROR) from None


def configure(payload, actor_id):
    """One first-save POST. Repetition is a conflict; recover with status GET."""
    from catchplate import db, operator_publication as publication
    from catchplate.development_sandbox import _open_directory
    pin = None
    try:
        _actor(actor_id)
        if type(payload) is profiles.XOAuthApplicationInput:
            payload = {**payload.model_dump(), "client_secret": payload.client_secret}
        _require(type(payload) is dict)
        value = profiles.XOAuthApplicationInput.model_validate(payload)
        directory = admission.require_runtime()
        public = profiles.public_record(profiles.build_profile(client_id=value.client_id,
            public_origin=admission.public_origin()))
        publication.assert_not_held()
        with publication.exclusive(), publication.closing_fd(_open_directory(publication._directory())) as descriptor:
            # This owner is never database bootstrap: refuse absent/replaced
            # retained storage before the ordinary writable connector can create it.
            identity = publication._database_identity(descriptor)
            with closing(db.connect()) as conn, conn:
                _require(publication._database_identity(descriptor) == identity)
                conn.execute("BEGIN IMMEDIATE")
                before, policy, existing, blocked = _snapshot(conn, directory)
                catalog.require_revision(conn, value.expected_revision)
                if policy["policy_hash"] != value.expected_policy_hash or existing is not None or blocked is not None:
                    raise catalog.CatalogConflict()
                _require(value.expected_revision < 9_007_199_254_740_990)
                # Absence of records, schema, custody and audit was proved above.
                # A valid orphan key from an earlier failed commit is reusable
                # only here, under the explicit first-save absence proof.
                pin = keys.initialize_first_x(directory, conn, no_retained_provider_state=True)
                owner = admission.admit_owner(pin.owner_id)
                bound = custody.bind_x(owner, config_version=1, public_profile=public)
                custody.install_empty_store(conn, owner)
                for _, _, sql in _DEFINITIONS:
                    conn.execute(sql)
                custody.insert_secret(conn, owner, bound, key=pin.material, secret=value.client_secret)
                record = {"schema": _BINDING_SCHEMA, "operation_id": value.operation_id,
                    "actor_id": actor_id, "owner_id": owner.owner_id, "config_version": 1,
                    "public_profile": public, "profile_binding_digest": profiles.parse_profile(public).binding_digest,
                    "reviewed_revision": value.expected_revision, "committed_revision": value.expected_revision + 1,
                    "policy_hash": value.expected_policy_hash, "created_at": db.iso_now()}
                conn.execute("INSERT INTO main.operator_x_configuration VALUES(1,?,?,?)",
                    (value.operation_id, actor_id, _canonical(record)))
                db.append_audit_event(conn, event_type=EVENT, actor_type="admin", actor_id=actor_id,
                    event=_audit_body(record), idempotency_key=_AUDIT_PREFIX + value.operation_id)
                catalog.advance_revision(conn, value.expected_revision)
                after, retained, checked, _ = _snapshot(conn, directory)
                _require(checked == record and retained == policy
                    and after == {**before, "revision": value.expected_revision + 1})
                keys.check_pin(pin)
                _require(publication._database_identity(descriptor) == identity)
                result = _operation(record)
                conn.commit()
            # Commit has returned, but a subsequent local failure still carries
            # no permission to repeat the POST. The actor can recover by GET.
            keys.check_pin(pin)
            _require(publication._database_identity(descriptor) == identity)
        # Publication is derived from the committed row, never a second save.
        # Its failure leaves readiness false; startup can materialize the same
        # retained record. Discovery and operation GETs remain read-only.
        try:
            from catchplate import operator_demo_store
            operator_demo_store.materialize()
        except Exception:
            pass
        return result
    except catalog.CatalogConflict:
        raise
    except Exception:
        raise ConfigurationUnavailable(_ERROR) from None
    finally:
        if pin is not None:
            try:
                keys.close_pin(pin)
            except Exception:
                raise ConfigurationUnavailable(_ERROR) from None
