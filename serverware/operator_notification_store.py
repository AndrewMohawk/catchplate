"""Operator-development notification settings and durable, at-most-attempted outbox.

The four slots are independent. Only explicit Save initializes notification-only
custody. Saving never sends. Source reads are committed read-only snapshots;
publication-owned writes atomically retain cursor/configuration/audit/outbox.
Network I/O is exclusively the worker's responsibility, outside every transaction.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Literal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from serverware import operator_notification_custody as custody
from serverware import operator_notification_events as events

SCHEMA = "serverware.operatorNotifications/v1"
OP_SCHEMA = "serverware.operatorNotificationOperation/v1"
SLOTS = ("action_required.slack", "action_required.webhook", "audit_log.slack", "audit_log.webhook")
STATES = ("queued", "sending", "acknowledged", "failed", "outcome_unknown", "suppressed", "expired")
MAX_QUEUE = 256
MAX_HISTORY = 10000
MAX_CONFIGURATIONS = 1024
# Legacy approval/JIT producers are not admitted operator-development sources.
# Native observations and host-trusted requests have separate typed boundaries;
# never turn this into a blanket action-source or operator-editable bypass.
ACTION_SOURCE_AVAILABLE = False
_PREFIX = "operator_notification_"
_PROCESS = str(uuid.uuid4())
_ERROR = "operator notifications unavailable"
_Slot = Literal["action_required.slack", "action_required.webhook", "audit_log.slack", "audit_log.webhook"]
_DEFINITIONS = {
    "meta": "CREATE TABLE operator_notification_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema TEXT NOT NULL, owner_id TEXT NOT NULL, cursor_json TEXT NOT NULL, last_channel TEXT NOT NULL) WITHOUT ROWID",
    "config": "CREATE TABLE operator_notification_config (slot TEXT NOT NULL, revision INTEGER NOT NULL, label TEXT NOT NULL, enabled INTEGER NOT NULL, event_types_json TEXT NOT NULL, max_attempts INTEGER NOT NULL, nonce BLOB, ciphertext BLOB, PRIMARY KEY(slot,revision)) WITHOUT ROWID",
    "operations": "CREATE TABLE operator_notification_operations (operation_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, kind TEXT NOT NULL, slot TEXT NOT NULL, revision INTEGER NOT NULL, created_at TEXT NOT NULL, delivery_id TEXT, slot_json TEXT) WITHOUT ROWID",
    "deliveries": "CREATE TABLE operator_notification_deliveries (delivery_id TEXT PRIMARY KEY, slot TEXT NOT NULL, revision INTEGER NOT NULL, source_event_id TEXT NOT NULL, payload_json TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL, due_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL, last_code TEXT, http_status INTEGER, claim_id TEXT, process_id TEXT, UNIQUE(slot,revision,source_event_id)) WITHOUT ROWID",
    "attempts": "CREATE TABLE operator_notification_attempts (delivery_id TEXT NOT NULL, attempt INTEGER NOT NULL, claim_id TEXT NOT NULL, started_ms INTEGER NOT NULL, finished_ms INTEGER, state TEXT NOT NULL, code TEXT, http_status INTEGER, PRIMARY KEY(delivery_id,attempt)) WITHOUT ROWID",
}


class NotificationUnavailable(RuntimeError):
    """Fixed non-secret admission, validation or retained-state failure."""


class NotificationConflict(RuntimeError):
    """Saved revision, operation identity, or bounded storage limit changed."""

    def __init__(self, message="notification configuration conflict", *, code="notification_conflict"):
        if code not in {"notification_revision_conflict", "notification_operation_conflict",
                "notification_capacity_conflict", "notification_conflict"}:
            raise ValueError("notification conflict code unavailable")
        self.code = code
        super().__init__(message)


class NotificationNotFound(LookupError):
    """No operation belongs to this exact actor and locator."""


class NotificationInputError(ValueError):
    """Definite fixed input rejection, before commit and without secret detail."""

    def __init__(self):
        super().__init__("notification input refused")


def _require(condition):
    if not condition:
        raise NotificationUnavailable(_ERROR)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _identifier(value):
    if type(value) is not str or str(uuid.UUID(value)) != value:
        raise ValueError("notification identifier refused")
    return value


def _actor(value):
    _require(type(value) is str and 1 <= len(value) <= 512 and value == value.strip()
        and all(32 <= ord(char) < 127 for char in value))


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    operation_id: str = Field(min_length=36, max_length=36)
    slot: _Slot
    expected_revision: int = Field(ge=0, le=MAX_CONFIGURATIONS)
    _uuid = field_validator("operation_id")(_identifier)


class SaveInput(_Input):
    label: str = Field(min_length=1, max_length=80)
    enabled: bool
    event_types: list[str] = Field(max_length=64)
    max_attempts: int = Field(ge=1, le=3)
    url_action: Literal["keep", "replace", "clear"]
    url: str | None = Field(default=None, min_length=1, max_length=4096, repr=False, exclude=True)

    @model_validator(mode="after")
    def bounded(self):
        if self.label != self.label.strip() or not all(32 <= ord(char) < 127 for char in self.label):
            raise ValueError("notification label refused")
        allowed = events.ACTION_EVENT_TYPES if self.slot.startswith("action_required.") else events.AUDIT_EVENT_TYPES
        if self.event_types != sorted(set(self.event_types)) or not set(self.event_types) <= set(allowed):
            raise ValueError("notification event selection refused")
        if (self.url_action == "replace") != (self.url is not None) or self.url_action == "clear" and self.enabled:
            raise ValueError("notification URL operation refused")
        return self


class TestInput(_Input):
    expected_revision: int = Field(ge=1, le=MAX_CONFIGURATIONS)


@dataclass(frozen=True)
class DeliveryClaim:
    delivery_id: str
    slot: str
    channel: str
    adapter: str
    revision: int
    payload: dict = field(repr=False)
    url: str = field(repr=False)
    attempt: int
    claim_id: str


def enabled() -> bool:
    """Disabled means no custody/database access; enabled requires real admission."""
    flag = os.getenv("SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED", "0")
    _require(flag in {"0", "1"})
    if flag == "0":
        return False
    from serverware import config, operator_demo, db, oauth_application_owner
    _require(operator_demo.active() and config.RELEASE_CHANNEL == "dev" and not config.PRODUCTION_IMAGE
        and config.TEE_PLATFORM == "none-dev" and config.TEE_QUOTE_PROVIDER == "dev-signed-quote"
        and not config.ATOMIC_RELEASE_AUTHORIZATION_ENABLED and not config.KEY_RELEASE_REQUIRED
        and oauth_application_owner.require_started() is None
        and not db.metadata_uses_postgres() and not db.audit_uses_postgres())
    return True


def _admit() -> Path:
    _require(enabled())
    from serverware import config
    raw = os.getenv("SERVERWARE_OPERATOR_NOTIFICATIONS_CUSTODY_DIR", "")
    path = Path(raw)
    _require(raw == str(path) and path.is_absolute() and path != Path("/") and ".." not in path.parts
        and all(33 <= ord(char) < 127 for char in raw)
        and not path.is_relative_to(config.DATA_DIR) and not config.DATA_DIR.is_relative_to(path))
    # Validate even before initialization without creating the mount or any file.
    with custody._directory(path):
        pass
    return path


@contextmanager
def _read():
    from serverware import config
    with closing(sqlite3.connect(config.DB_PATH.as_uri() + "?mode=ro", uri=True, timeout=0)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA read_uncommitted=OFF")
        conn.execute("BEGIN")
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        yield conn


@contextmanager
def _write():
    from serverware import db, operator_publication
    with operator_publication.exclusive(), closing(db.connect()) as conn:
        _require(type(conn) is sqlite3.Connection)
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise


def _cursor(value):
    result = json.loads(value)
    _require(type(result) is dict and set(result) == {"rowid", "event_id", "event_hash"})
    _require(type(result["rowid"]) is int and 0 <= result["rowid"] <= 9007199254740991)
    if result["rowid"] == 0:
        _require(result["event_id"] is None and result["event_hash"] is None)
    else:
        _require(type(result["event_id"]) is str and 1 <= len(result["event_id"]) <= 256
            and all(32 <= ord(char) < 127 for char in result["event_id"])
            and type(result["event_hash"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", result["event_hash"]) is not None)
    return events.EventCursor(**result)


def _cursor_json(value):
    return _canonical({"rowid": value.rowid, "event_id": value.event_id, "event_hash": value.event_hash})


def _meta(conn):
    objects = conn.execute("SELECT name,type,sql FROM sqlite_master WHERE lower(name) GLOB ? OR lower(tbl_name) GLOB ?",
        (_PREFIX + "*", _PREFIX + "*")).fetchall()
    if not objects:
        _require(conn.execute("SELECT 1 FROM audit_events WHERE event_type LIKE 'notification.%' LIMIT 1").fetchone() is None)
        return None
    expected = {_PREFIX + key: sql for key, sql in _DEFINITIONS.items()}
    # SQLite's implicit autoindexes are allowed only for the declared tables.
    declared = [row for row in objects if row["sql"] is not None]
    _require(len(declared) == len(expected) and {row["name"] for row in declared} == set(expected))
    for row in declared:
        _require(row["type"] == "table" and row["sql"] == expected[row["name"]])
    rows = conn.execute("SELECT * FROM operator_notification_meta LIMIT 2").fetchall()
    _require(len(rows) == 1)
    result = dict(rows[0])
    _require(result["singleton"] == 1 and result["schema"] == SCHEMA
        and _identifier(result["owner_id"]) == result["owner_id"]
        and result["last_channel"] in {"action_required", "audit_log"})
    _cursor(result["cursor_json"])
    return result


def _key(conn, path):
    meta = _meta(conn)
    return meta, custody.read(path, meta["owner_id"]) if meta else None


def _config(conn, slot, revision=None):
    if revision is None:
        row = conn.execute("SELECT * FROM operator_notification_config WHERE slot=? ORDER BY revision DESC LIMIT 1", (slot,)).fetchone()
    else:
        row = conn.execute("SELECT * FROM operator_notification_config WHERE slot=? AND revision=?", (slot, revision)).fetchone()
    if row is None:
        return None
    result = dict(row)
    _require(result["slot"] in SLOTS and type(result["revision"]) is int and 1 <= result["revision"] <= MAX_CONFIGURATIONS
        and result["enabled"] in {0, 1} and type(result["max_attempts"]) is int and 1 <= result["max_attempts"] <= 3)
    event_types = json.loads(result["event_types_json"])
    SaveInput(operation_id="00000000-0000-0000-0000-000000000000", slot=result["slot"],
        expected_revision=result["revision"], label=result["label"], enabled=bool(result["enabled"]),
        event_types=event_types, max_attempts=result["max_attempts"], url_action="keep")
    _require((result["nonce"] is None) == (result["ciphertext"] is None))
    if result["nonce"] is not None:
        _require(type(result["nonce"]) is bytes and len(result["nonce"]) == 12
            and type(result["ciphertext"]) is bytes and 17 <= len(result["ciphertext"]) <= 4112)
    else:
        _require(not result["enabled"])
    result["event_types"] = event_types
    return result


def _delivery(row):
    if row is None:
        return None
    from serverware.operator_notification_transport import DELIVERY_CODES
    allowed_codes = DELIVERY_CODES | {"configuration_changed", "action_no_longer_current", "action_expired", "action_source_unavailable", "native_source_unavailable", "host_source_unavailable"}
    _require(row["status"] in STATES and (row["last_code"] is None or row["last_code"] in allowed_codes)
        and _identifier(row["delivery_id"]) == row["delivery_id"] and type(row["attempts"]) is int and 0 <= row["attempts"] <= 3
        and (row["http_status"] is None or type(row["http_status"]) is int and 200 <= row["http_status"] <= 599))
    _time(row["created_ms"])
    _time(row["updated_ms"])
    return {"delivery_id": row["delivery_id"], "status": row["status"], "attempts": row["attempts"],
        "code": row["last_code"], "http_status": row["http_status"], "created_at_epoch_ms": row["created_ms"],
        "updated_at_epoch_ms": row["updated_ms"]}


def _slot(slot, config=None, last=None):
    channel, adapter = slot.split(".")
    return {"slot": slot, "channel": channel, "adapter": adapter, "revision": config["revision"] if config else 0,
        "label": config["label"] if config else "", "enabled": bool(config["enabled"]) if config else False,
        "secret_present": config["nonce"] is not None if config else False,
        "event_types": config["event_types"] if config else [], "max_attempts": config["max_attempts"] if config else 1,
        "last_delivery": _delivery(last)}


def _safe_errors(function):
    from functools import wraps
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (NotificationConflict, NotificationNotFound, NotificationInputError):
            raise
        except (OSError, ValueError, TypeError, RuntimeError, sqlite3.Error, KeyError, AttributeError, IndexError):
            raise NotificationUnavailable(_ERROR) from None
    return wrapped


@_safe_errors
def status():
    result = {"schema": SCHEMA, "available": enabled(), "slots": [_slot(slot) for slot in SLOTS],
        "queue": {state: 0 for state in STATES}, "cursor": None,
        "backlog": {"pending_source_events": 0, "queue_capacity": MAX_QUEUE, "retained_capacity": MAX_HISTORY}}
    if not result["available"]:
        return result
    path = _admit()
    with _read() as conn:
        meta, _ = _key(conn, path)
        if not meta:
            return result
        result["cursor"] = json.loads(meta["cursor_json"])
        result["backlog"]["pending_source_events"] = conn.execute("SELECT count(*) FROM audit_events WHERE rowid>?",
            (_cursor(meta["cursor_json"]).rowid,)).fetchone()[0]
        for position, slot in enumerate(SLOTS):
            last = conn.execute("SELECT * FROM operator_notification_deliveries WHERE slot=? ORDER BY created_ms DESC,delivery_id DESC LIMIT 1", (slot,)).fetchone()
            result["slots"][position] = _slot(slot, _config(conn, slot), last)
        for row in conn.execute("SELECT status,count(*) AS n FROM operator_notification_deliveries GROUP BY status"):
            _require(row["status"] in STATES)
            result["queue"][row["status"]] = row["n"]
    return result


def _operation(conn, operation_id, actor):
    row = conn.execute("SELECT * FROM operator_notification_operations WHERE operation_id=? AND actor_id=?", (operation_id, actor)).fetchone()
    if row is None:
        raise NotificationNotFound("notification operation not found")
    _identifier(row["operation_id"])
    _actor(row["actor_id"])
    _require(row["slot"] in SLOTS and type(row["revision"]) is int and 1 <= row["revision"] <= MAX_CONFIGURATIONS
        and type(row["created_at"]) is str and len(row["created_at"]) <= 64
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?\+00:00", row["created_at"]) is not None)
    configuration = _config(conn, row["slot"], row["revision"])
    _require(configuration is not None)
    delivery = None
    snapshot = None
    if row["kind"] == "save":
        snapshot = _slot(row["slot"], configuration)
        _require(row["delivery_id"] is None and row["slot_json"] == _canonical(snapshot))
    else:
        _require(row["kind"] == "test" and row["slot_json"] is None)
        _identifier(row["delivery_id"])
        delivery = conn.execute("SELECT * FROM operator_notification_deliveries WHERE delivery_id=?", (row["delivery_id"],)).fetchone()
        _require(delivery is not None and delivery["slot"] == row["slot"] and delivery["revision"] == row["revision"]
            and delivery["source_event_id"] == "test:" + operation_id
            and delivery["payload_json"] == _canonical(_test_payload(operation_id, row["slot"], row["created_at"])))
        _delivery(delivery)
    return {"schema": OP_SCHEMA, "operation_id": row["operation_id"], "kind": row["kind"], "slot": row["slot"],
        "revision": row["revision"], "status": delivery["status"] if delivery else "saved", "delivery_id": row["delivery_id"],
        "slot_state": snapshot}


@_safe_errors
def operation_status(operation_id, actor):
    _identifier(operation_id)
    _actor(actor)
    path = _admit()
    with _read() as conn:
        meta, _ = _key(conn, path)
        if not meta:
            raise NotificationNotFound("notification operation not found")
        return _operation(conn, operation_id, actor)


def _audit(conn, payload, actor, kind, revision):
    from serverware import db
    db.append_audit_event(conn, event_type="notification." + kind, actor_type="admin", actor_id=actor,
        idempotency_key="notification:" + payload.operation_id,
        event={"schema": OP_SCHEMA, "operation_id": payload.operation_id, "slot": payload.slot,
            "revision": revision, "kind": kind})


def _new_operation(conn, payload, actor):
    if conn.execute("SELECT 1 FROM operator_notification_operations WHERE operation_id=?", (payload.operation_id,)).fetchone():
        raise NotificationConflict("notification operation already retained; inspect its status", code="notification_operation_conflict")
    if conn.execute("SELECT count(*) FROM operator_notification_operations").fetchone()[0] >= MAX_HISTORY:
        raise NotificationConflict("notification retained-operation limit reached", code="notification_capacity_conflict")


def _now():
    return int(time.time() * 1000)


def _time(value):
    _require(type(value) is int and 0 <= value <= 253402300799000)
    return value


def _iso(value):
    return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat()


@_safe_errors
def save(payload, actor):
    _actor(actor)
    if isinstance(payload, SaveInput):
        payload = {**payload.model_dump(), "url": payload.url}
    payload = SaveInput.model_validate(payload)
    path = _admit()
    from serverware import operator_notification_transport as transport
    policy = transport.parse_egress_policy(os.getenv("SERVERWARE_OPERATOR_NOTIFICATIONS_PRIVATE_DESTINATIONS_JSON", '{"bindings":[]}'))
    if payload.url_action == "replace":
        try:
            transport.validate_destination(payload.slot.split(".")[1], payload.url, policy)
        except transport.DestinationError:
            raise NotificationInputError() from None
    # Baseline from an independently committed, query-only source snapshot.
    with _read() as conn:
        before = _meta(conn)
        baseline = events.head_cursor(conn) if before is None else None
    with _write() as conn:
        meta, key = _key(conn, path)
        if meta is None:
            _require(before is None)
            if payload.expected_revision != 0:
                raise NotificationConflict("notification saved revision changed", code="notification_revision_conflict")
            if payload.url_action != "replace":
                raise NotificationInputError()
            key = custody.initialize(path, no_retained_notification_state=True)
            for sql in _DEFINITIONS.values():
                conn.execute(sql)
            conn.execute("INSERT INTO operator_notification_meta VALUES (1,?,?,?,?)",
                (SCHEMA, key.owner_id, _cursor_json(baseline), "audit_log"))
        _new_operation(conn, payload, actor)
        previous = _config(conn, payload.slot)
        revision = previous["revision"] if previous else 0
        if revision != payload.expected_revision:
            raise NotificationConflict("notification saved revision changed", code="notification_revision_conflict")
        if conn.execute("SELECT count(*) FROM operator_notification_config").fetchone()[0] >= MAX_CONFIGURATIONS:
            raise NotificationConflict("notification configuration retention limit reached", code="notification_capacity_conflict")
        url = payload.url
        if payload.url_action == "keep":
            if previous is None or previous["nonce"] is None:
                raise NotificationInputError()
            url = custody.unseal(key, payload.slot, revision, previous["nonce"], previous["ciphertext"])
        nonce, ciphertext = custody.seal(key, payload.slot, revision + 1, url) if url is not None else (None, None)
        conn.execute("INSERT INTO operator_notification_config VALUES (?,?,?,?,?,?,?,?)",
            (payload.slot, revision + 1, payload.label, int(payload.enabled), _canonical(payload.event_types), payload.max_attempts, nonce, ciphertext))
        now = _now()
        conn.execute("UPDATE operator_notification_deliveries SET status='suppressed',last_code='configuration_changed',updated_ms=? WHERE slot=? AND status='queued'", (now, payload.slot))
        snapshot = _slot(payload.slot, _config(conn, payload.slot))
        conn.execute("INSERT INTO operator_notification_operations VALUES (?,?,?,?,?,?,NULL,?)",
            (payload.operation_id, actor, "save", payload.slot, revision + 1, _iso(now), _canonical(snapshot)))
        _audit(conn, payload, actor, "save", revision + 1)
        return _operation(conn, payload.operation_id, actor)


def _capacity(conn, addition, retained_addition=None):
    queued = conn.execute("SELECT count(*) FROM operator_notification_deliveries WHERE status IN ('queued','sending')").fetchone()[0]
    history = conn.execute("SELECT count(*) FROM operator_notification_deliveries").fetchone()[0]
    if queued + addition > MAX_QUEUE or history + (addition if retained_addition is None else retained_addition) > MAX_HISTORY:
        raise NotificationConflict("notification outbox is full; source cursor retained", code="notification_capacity_conflict")


def _enqueue(conn, slot, revision, source_event_id, payload, now):
    delivery_id = str(uuid.uuid4())
    encoded = _canonical(payload)
    _require(len(encoded.encode("ascii")) <= 12288)
    conn.execute("INSERT INTO operator_notification_deliveries VALUES (?,?,?,?,?,'queued',0,?,?,?,NULL,NULL,NULL,NULL)",
        (delivery_id, slot, revision, source_event_id, encoded, now, now, now))
    return delivery_id


def _test_payload(operation_id, slot, created_at):
    return {"schema": "serverware.operatorNotification/v1", "channel": slot.split(".")[0],
        "source": {"event_id": "test:" + operation_id, "event_hash": None, "event_type": "notification.test", "created_at": created_at},
        "summary": "Serverware synthetic notification test", "review_path": "/#audit", "details": {"synthetic": True}, "test": True}


@_safe_errors
def queue_test(payload, actor):
    _actor(actor)
    payload = TestInput.model_validate(payload.model_dump() if isinstance(payload, TestInput) else payload)
    path = _admit()
    with _write() as conn:
        meta, _ = _key(conn, path)
        _require(meta is not None)
        _new_operation(conn, payload, actor)
        configuration = _config(conn, payload.slot)
        if not configuration or configuration["revision"] != payload.expected_revision or not configuration["enabled"]:
            raise NotificationConflict("notification saved revision is unavailable or disabled", code="notification_revision_conflict")
        _capacity(conn, 1)
        now = _now()
        notice = _test_payload(payload.operation_id, payload.slot, _iso(now))
        identifier = _enqueue(conn, payload.slot, payload.expected_revision, "test:" + payload.operation_id, notice, now)
        conn.execute("INSERT INTO operator_notification_operations VALUES (?,?,?,?,?,?,?,NULL)",
            (payload.operation_id, actor, "test", payload.slot, payload.expected_revision, _iso(now), identifier))
        _audit(conn, payload, actor, "test", payload.expected_revision)
        return _operation(conn, payload.operation_id, actor)


@_safe_errors
def record_native_observation(notice, now_epoch_ms):
    """Internal typed bridge ingestion; no HTTP/API or relay read inside this owner.

The worker obtains a closed observation from the separately admitted Unix source
before calling. One deterministic core-audit row is appended atomically; the
normal cursor later fans out independent action/audit copies. An exact duplicate
is a no-op, while any ID reuse with different retained content fails closed.
"""
    from serverware.operator_notification_pilot_source import NativePilotNotice, notice_record
    now = _time(now_epoch_ms)
    _require(type(notice) is NativePilotNotice)
    record = events._native_record(notice_record(notice))
    expires = int(record["observation"]["sourceExpiresAtUnixNanos"])
    if max(now * 1_000_000, time.time_ns()) >= expires:
        return None
    identifier = events.native_event_identifier(record)
    path = _admit()
    from serverware import db
    with _write() as conn:
        meta, _ = _key(conn, path)
        if meta is None or max(now * 1_000_000, time.time_ns()) >= expires:
            return None
        exists = conn.execute("SELECT 1 FROM audit_events WHERE id=?", (identifier,)).fetchone() is not None
        retained = db.append_audit_event(conn, event_type=events.NATIVE_OBSERVATION_TYPE,
            actor_type="system", actor_id="native-pilot-observer", event=record, idempotency_key=identifier)
        _require(retained["id"] == identifier and retained["event_type"] == events.NATIVE_OBSERVATION_TYPE
            and retained["actor_type"] == "system" and retained["actor_id"] == "native-pilot-observer"
            and events._same_projection(retained["event"], record))
        return {"recorded": not exists, "event_id": identifier}


def host_source_available() -> bool:
    """Fresh host gate observation, only outside store/publication transactions."""
    from serverware import operator_host_approvals as host
    return host.enabled() and host.available()


def _host_owned(payload):
    from serverware import config
    return (events.host_action_payload(payload)
        and payload["details"]["host_approval"]["reviewer_id"] == config.ADMIN_USER_ID)


def _action_admitted(payload, *, host_available=False):
    return (payload.get("test") is True or events.native_action_payload(payload)
        or host_available and _host_owned(payload)
        or ACTION_SOURCE_AVAILABLE is True)


@_safe_errors
def consume_events(now_epoch_ms):
    now = _time(now_epoch_ms)
    path = _admit()
    host_available = host_source_available()
    with _read() as conn:
        meta, _ = _key(conn, path)
        if not meta:
            return {"consumed": 0, "queued": 0}
        old_cursor = meta["cursor_json"]
        candidates, cursor = events.read_batch(conn, _cursor(old_cursor), limit=32, now_epoch_ms=now)
    with _write() as conn:
        current_meta, _ = _key(conn, path)
        if current_meta["cursor_json"] != old_cursor:
            raise NotificationConflict("notification source cursor changed")
        additions = []
        for slot in SLOTS:
            configuration = _config(conn, slot)
            if not configuration or not configuration["enabled"]:
                continue
            for source in candidates:
                notice = source.action_payload if slot.startswith("action_required.") else source.audit_payload
                selection = source.filter_event_type or source.event_type
                if notice is not None and selection in configuration["event_types"]:
                    additions.append((slot, configuration["revision"], source.event_id, notice))
        active = sum(not slot.startswith("action_required.") or _action_admitted(notice, host_available=host_available)
            for slot, _, _, notice in additions)
        _capacity(conn, active, len(additions))
        for slot, revision, source_event_id, notice in additions:
            identifier = _enqueue(conn, slot, revision, source_event_id, notice, now)
            if slot.startswith("action_required.") and not _action_admitted(notice, host_available=host_available):
                conn.execute("UPDATE operator_notification_deliveries SET status='suppressed',last_code='action_source_unavailable' WHERE delivery_id=?", (identifier,))
        conn.execute("UPDATE operator_notification_meta SET cursor_json=? WHERE singleton=1", (_cursor_json(cursor),))
        return {"consumed": cursor.rowid - _cursor(old_cursor).rowid, "queued": active, "suppressed": len(additions) - active}


def _terminal(conn, delivery, state, code, now, http_status=None):
    conn.execute("UPDATE operator_notification_deliveries SET status=?,last_code=?,http_status=?,updated_ms=? WHERE delivery_id=?",
        (state, code, http_status, now, delivery["delivery_id"]))
    if delivery["status"] == "sending":
        conn.execute("UPDATE operator_notification_attempts SET finished_ms=?,state=?,code=?,http_status=? WHERE delivery_id=? AND attempt=? AND claim_id=? AND finished_ms IS NULL",
            (now, state, code, http_status, delivery["delivery_id"], delivery["attempts"], delivery["claim_id"]))


def _recover_sending(conn, now):
    # A different process UUID is not proof that its owner died. Only age beyond
    # the 10s transport deadline plus 50s grace terminalizes an uncertain attempt;
    # it is never returned to queued, including after a restart.
    for row in conn.execute("SELECT * FROM operator_notification_deliveries WHERE status='sending' AND updated_ms<?", (now - 60000,)).fetchall():
        _terminal(conn, row, "outcome_unknown", "delivery_unknown", now)


@_safe_errors
def claim_next(now_epoch_ms):
    now = _time(now_epoch_ms)
    path = _admit()
    host_available = host_source_available()
    with _write() as conn:
        meta, key = _key(conn, path)
        if not meta:
            return None
        _recover_sending(conn, now)
        preference = "audit_log" if meta["last_channel"] == "action_required" else "action_required"
        pending = conn.execute("SELECT * FROM operator_notification_deliveries WHERE status='queued' AND due_ms<=? ORDER BY CASE WHEN slot LIKE ? THEN 0 ELSE 1 END,created_ms,delivery_id LIMIT ?",
            (now, preference + ".%", MAX_QUEUE)).fetchall()
        for row in pending:
            payload = json.loads(row["payload_json"])
            _require(type(payload) is dict)
            if row["slot"].startswith("action_required.") and not _action_admitted(payload, host_available=host_available):
                _terminal(conn, row, "suppressed", "action_source_unavailable", now)
                continue
            configuration = _config(conn, row["slot"])
            if not configuration or not configuration["enabled"] or configuration["revision"] != row["revision"]:
                _terminal(conn, row, "suppressed", "configuration_changed", now)
                continue
            _require(row["attempts"] < configuration["max_attempts"])
            url = custody.unseal(key, row["slot"], row["revision"], configuration["nonce"], configuration["ciphertext"])
            claim_id = str(uuid.uuid4())
            attempt = row["attempts"] + 1
            conn.execute("UPDATE operator_notification_deliveries SET status='sending',attempts=?,claim_id=?,process_id=?,updated_ms=? WHERE delivery_id=?",
                (attempt, claim_id, _PROCESS, now, row["delivery_id"]))
            conn.execute("INSERT INTO operator_notification_attempts VALUES (?,?,?,?,NULL,'sending',NULL,NULL)",
                (row["delivery_id"], attempt, claim_id, now))
            channel, adapter = row["slot"].split(".")
            conn.execute("UPDATE operator_notification_meta SET last_channel=? WHERE singleton=1", (channel,))
            return DeliveryClaim(row["delivery_id"], row["slot"], channel, adapter, row["revision"], payload, url, attempt, claim_id)
    return None


def _claimed(conn, claim):
    _require(type(claim) is DeliveryClaim)
    _require(claim.slot in SLOTS and claim.channel == claim.slot.split(".")[0] and claim.adapter == claim.slot.split(".")[1])
    row = conn.execute("SELECT * FROM operator_notification_deliveries WHERE delivery_id=?", (claim.delivery_id,)).fetchone()
    _require(row is not None and row["slot"] == claim.slot and row["revision"] == claim.revision
        and row["attempts"] == claim.attempt and row["claim_id"] == claim.claim_id and row["process_id"] == _PROCESS
        and _canonical(claim.payload) == row["payload_json"])
    return row


def is_native_action(claim) -> bool:
    """Closed native action recognition, not a live-source assertion."""
    return (type(claim) is DeliveryClaim and claim.channel == "action_required"
        and claim.slot in {"action_required.slack", "action_required.webhook"}
        and events.native_action_payload(claim.payload))


def is_host_action(claim) -> bool:
    """Closed host action recognition; not permission to decide or dispatch."""
    return (type(claim) is DeliveryClaim and claim.channel == "action_required"
        and claim.slot in {"action_required.slack", "action_required.webhook"}
        and events.host_action_payload(claim.payload))


@_safe_errors
def suppress_native_claim(claim, now_epoch_ms):
    """Retain a fixed refusal after the worker's outside-lock relay recheck."""
    now = _time(now_epoch_ms)
    _require(is_native_action(claim))
    path = _admit()
    with _write() as conn:
        _key(conn, path)
        row = _claimed(conn, claim)
        if row["status"] == "sending":
            _terminal(conn, row, "suppressed", "native_source_unavailable", now)
    return False


@_safe_errors
def current(claim, now_epoch_ms):
    now = _time(now_epoch_ms)
    path = _admit()
    reason = None
    host_available = host_source_available() if is_host_action(claim) else False
    with _read() as conn:
        meta, _ = _key(conn, path)
        _require(meta is not None)
        row = _claimed(conn, claim)
        if row["status"] != "sending":
            return False
        configuration = _config(conn, claim.slot)
        if not configuration or not configuration["enabled"] or configuration["revision"] != claim.revision:
            reason = "configuration_changed"
        elif claim.payload.get("test") is True:
            test = conn.execute("SELECT * FROM operator_notification_operations WHERE kind='test' AND delivery_id=?", (claim.delivery_id,)).fetchone()
            _require(test is not None and test["slot"] == claim.slot and test["revision"] == claim.revision
                and claim.payload == _test_payload(test["operation_id"], test["slot"], test["created_at"]))
            _operation(conn, test["operation_id"], test["actor_id"])
        elif claim.channel == "action_required":
            if is_native_action(claim):
                original_expiry = events.native_expiry_unix_nanos(claim.payload)
                current_nanos = max(now * 1_000_000, time.time_ns())
                if current_nanos >= original_expiry:
                    reason = "action_expired"
                elif not events.native_action_matches_source(conn, claim.payload, now_unix_nanos=current_nanos):
                    reason = "native_source_unavailable"
            elif is_host_action(claim):
                from serverware import config
                current_ms = max(now, _now())
                if current_ms >= events._epoch(claim.payload["expires_at"]):
                    reason = "action_expired"
                elif not host_available or not _host_owned(claim.payload):
                    reason = "host_source_unavailable"
                elif not events.host_action_matches_source(conn, claim.payload,
                        reviewer_id=config.ADMIN_USER_ID, now_epoch_ms=current_ms):
                    reason = "action_no_longer_current"
            elif not ACTION_SOURCE_AVAILABLE:
                reason = "action_source_unavailable"
            elif not events.action_is_current(conn, claim.payload, now_epoch_ms=now):
                expires = datetime.fromisoformat(claim.payload["expires_at"].replace("Z", "+00:00"))
                reason = "action_expired" if int(expires.timestamp() * 1000) <= now else "action_no_longer_current"
        else:
            _require(events.payload_matches_source(conn, claim.payload, now_epoch_ms=now))
    # Recheck after the read transaction and custody directory checks finish.
    # An entry timestamp must not extend the native owner's original nanoseconds.
    if reason is None and is_native_action(claim):
        final_expiry = events.native_expiry_unix_nanos(claim.payload)
        if time.time_ns() >= final_expiry:
            reason = "action_expired"
    if reason is None and is_host_action(claim) and _now() >= events._epoch(claim.payload["expires_at"]):
        reason = "action_expired"
    if reason:
        with _write() as conn:
            _key(conn, path)
            row = _claimed(conn, claim)
            if row["status"] == "sending":
                _terminal(conn, row, "expired" if reason == "action_expired" else "suppressed", reason, now)
        return False
    return True


@_safe_errors
def finish(claim, result, now_epoch_ms):
    from serverware.operator_notification_transport import DeliveryResult
    _require(type(result) is DeliveryResult)
    now = _time(now_epoch_ms)
    path = _admit()
    with _write() as conn:
        _key(conn, path)
        row = _claimed(conn, claim)
        if row["status"] != "sending":
            return _delivery(row)
        _terminal(conn, row, result.state, result.code, now, result.http_status)
        configuration = _config(conn, claim.slot)
        if (result.retryable and configuration and configuration["enabled"] and configuration["revision"] == claim.revision
                and claim.attempt < configuration["max_attempts"]):
            delay = 30000 if claim.attempt == 1 else 120000
            conn.execute("UPDATE operator_notification_deliveries SET status='queued',due_ms=? WHERE delivery_id=?", (now + delay, claim.delivery_id))
        return _delivery(conn.execute("SELECT * FROM operator_notification_deliveries WHERE delivery_id=?", (claim.delivery_id,)).fetchone())
