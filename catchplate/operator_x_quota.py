"""Durable posting-attempt quotas for explicitly selected ordinary X routes.

The caller owns publication EX, BEGIN IMMEDIATE and commit/acknowledgement.
There is no HTTP, token opening, native fallback, retry, cancellation or refund.
Only a successful first claim permits the caller to proceed toward one send;
losing that acknowledgement still consumes the attempt. Unbounded routes keep
their existing path and their intervening posts are not retrospectively counted.

This is the existing trusted-host SQLite profile, not rollback-resistant native
authority. Exact schema, an independent retained audit initialization marker,
immutable identity/deletion guards and current bucket anchors detect missing
required state. They do not claim protection against a privileged replacement
of the complete database and audit history. Request work uses indexed current
rows; it does not scan or rehash the ever-growing claimed-attempt history.
"""
from __future__ import annotations

from contextlib import contextmanager
from functools import wraps
import hashlib
import json
import os
import re
import sqlite3
import time
import uuid

from catchplate import operator_catalog_schema as catalog
from catchplate import operator_x_admission as admission

FLAG = "CATCHPLATE_OPERATOR_X_POST_ATTEMPT_QUOTA_ENABLED"
PREFIX = "operator_x_quota_"
STATE, ACCOUNTS, BUCKETS, ATTEMPTS = (PREFIX + name for name in
    ("state", "accounts", "buckets", "attempts"))
INITIALIZED = "operator_x.quota.initialized"
RESERVATION_SCHEMA = "catchplate.operatorXPostingQuotaReservation/v1"
CLAIM_SCHEMA = "catchplate.operatorXPostingQuotaClaim/v1"
DAY_MS, MAX_TTL_MS, MAX_OUTSTANDING = 86_400_000, 5_000, 1024
MAX_INTEGER = 9_007_199_254_740_991
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SUBJECT = re.compile(r"[1-9][0-9]{0,19}\Z")
BINDING_FIELDS = frozenset({"principal_id", "route_id", "credential_id", "credential_version",
    "credential_metadata_digest", "policy_hash", "request_digest", "operation_digest",
    "attempt_nonce", "recipient_digest", "request_binding_digest", "expires_at_epoch_ms"})
_DIGEST_FIELDS = BINDING_FIELDS - {"principal_id", "route_id", "credential_id",
    "credential_version", "expires_at_epoch_ms"}

_DDL = {
    STATE: f"""CREATE TABLE {STATE} (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        schema_version INTEGER NOT NULL CHECK(schema_version=1),
        initialization_id TEXT NOT NULL, initialization_hash TEXT NOT NULL,
        initialized_at_epoch_ms INTEGER NOT NULL CHECK(initialized_at_epoch_ms>0),
        wall_highwater_ms INTEGER NOT NULL CHECK(wall_highwater_ms>=initialized_at_epoch_ms))""",
    ACCOUNTS: f"""CREATE TABLE {ACCOUNTS} (
        provider_subject TEXT PRIMARY KEY, last_day INTEGER NOT NULL CHECK(last_day>=0),
        created_at_epoch_ms INTEGER NOT NULL CHECK(created_at_epoch_ms>0))""",
    BUCKETS: f"""CREATE TABLE {BUCKETS} (
        bucket_key TEXT PRIMARY KEY, provider_subject TEXT NOT NULL,
        utc_day INTEGER NOT NULL CHECK(utc_day>=0),
        claimed INTEGER NOT NULL CHECK(claimed>=0 AND claimed<={MAX_INTEGER}),
        outstanding INTEGER NOT NULL CHECK(outstanding>=0 AND outstanding<={MAX_OUTSTANDING}),
        UNIQUE(provider_subject,utc_day))""",
    ATTEMPTS: f"""CREATE TABLE {ATTEMPTS} (
        reservation_id TEXT PRIMARY KEY, attempt_nonce TEXT NOT NULL UNIQUE,
        bucket_key TEXT NOT NULL, provider_subject TEXT NOT NULL, utc_day INTEGER NOT NULL,
        binding_json TEXT NOT NULL CHECK(length(CAST(binding_json AS BLOB))<=4096),
        binding_digest TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('reserved','claimed','expired')),
        created_at_epoch_ms INTEGER NOT NULL, expires_at_epoch_ms INTEGER NOT NULL,
        claimed_at_epoch_ms INTEGER,
        CHECK(expires_at_epoch_ms>created_at_epoch_ms AND
            expires_at_epoch_ms<=created_at_epoch_ms+{MAX_TTL_MS}),
        CHECK((state='claimed' AND claimed_at_epoch_ms>=created_at_epoch_ms AND
            claimed_at_epoch_ms<expires_at_epoch_ms) OR
            (state!='claimed' AND claimed_at_epoch_ms IS NULL)))""",
    PREFIX + "expiry": f"CREATE INDEX {PREFIX}expiry ON {ATTEMPTS}(bucket_key,state,expires_at_epoch_ms)",
    PREFIX + "subject": f"CREATE INDEX {PREFIX}subject ON {ATTEMPTS}(provider_subject)",
}
for _table in (STATE, ACCOUNTS, BUCKETS, ATTEMPTS):
    _name = _table + "_no_delete"
    _DDL[_name] = (f"CREATE TRIGGER {_name} BEFORE DELETE ON {_table} BEGIN "
        "SELECT RAISE(ABORT,'operator X quota deletion refused'); END")
_DDL[STATE + "_update"] = f"""CREATE TRIGGER {STATE}_update BEFORE UPDATE ON {STATE}
    WHEN NEW.singleton!=OLD.singleton OR NEW.schema_version!=OLD.schema_version OR
        NEW.initialization_id!=OLD.initialization_id OR NEW.initialization_hash!=OLD.initialization_hash OR
        NEW.initialized_at_epoch_ms!=OLD.initialized_at_epoch_ms OR NEW.wall_highwater_ms<OLD.wall_highwater_ms
    BEGIN SELECT RAISE(ABORT,'operator X quota state refused'); END"""
_DDL[ACCOUNTS + "_update"] = f"""CREATE TRIGGER {ACCOUNTS}_update BEFORE UPDATE ON {ACCOUNTS}
    WHEN NEW.provider_subject!=OLD.provider_subject OR NEW.last_day<OLD.last_day OR
        NEW.created_at_epoch_ms!=OLD.created_at_epoch_ms
    BEGIN SELECT RAISE(ABORT,'operator X quota account refused'); END"""
_DDL[BUCKETS + "_update"] = f"""CREATE TRIGGER {BUCKETS}_update BEFORE UPDATE ON {BUCKETS}
    WHEN NEW.bucket_key!=OLD.bucket_key OR NEW.provider_subject!=OLD.provider_subject OR
        NEW.utc_day!=OLD.utc_day OR NEW.claimed<OLD.claimed
    BEGIN SELECT RAISE(ABORT,'operator X quota counter refused'); END"""
_IMMUTABLE_ATTEMPT = ("reservation_id", "attempt_nonce", "bucket_key", "provider_subject", "utc_day",
    "binding_json", "binding_digest", "created_at_epoch_ms", "expires_at_epoch_ms")
_DDL[ATTEMPTS + "_update"] = (f"CREATE TRIGGER {ATTEMPTS}_update BEFORE UPDATE ON {ATTEMPTS} WHEN "
    + " OR ".join(f"NEW.{key}!=OLD.{key}" for key in _IMMUTABLE_ATTEMPT)
    + " OR OLD.state!='reserved' OR NEW.state NOT IN ('claimed','expired') "
    "BEGIN SELECT RAISE(ABORT,'operator X quota transition refused'); END")
_AUTO_INDEXES = {f"sqlite_autoindex_{table}_{number}" for table, number in
    ((ACCOUNTS, 1), (BUCKETS, 1), (BUCKETS, 2), (ATTEMPTS, 1), (ATTEMPTS, 2))}


class QuotaUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("operator X posting quota unavailable")


class QuotaExceeded(QuotaUnavailable):
    def __init__(self):
        RuntimeError.__init__(self, "operator X posting-attempt quota exhausted")


class QuotaConflict(QuotaUnavailable):
    def __init__(self):
        RuntimeError.__init__(self, "operator X posting quota request expired or already used")


def _need(value):
    if not value:
        raise QuotaUnavailable()


def _closed(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except QuotaUnavailable:
            raise
        except Exception:
            raise QuotaUnavailable() from None
    return call


def enabled():
    value = os.getenv(FLAG, "0")
    _need(value in {"0", "1"})
    return value == "1"


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _digest(value):
    return "sha256:" + hashlib.sha256(_json(value).encode("ascii")).hexdigest()


def _load(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result)
            result[key] = value
        return result
    _need(type(raw) is str and len(raw.encode("utf-8")) <= 32768)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: _need(False))


def _uuid(value):
    return type(value) is str and len(value) == 36 and str(uuid.UUID(value)) == value


def _integer(value, minimum=1):
    return type(value) is int and minimum <= value <= MAX_INTEGER


def _clock():
    value = time.time_ns() // 1_000_000
    _need(_integer(value))
    return value


def _transaction(conn, *, writing=False):
    from catchplate import operator_publication as publication
    _need(enabled())
    directory = admission.require_runtime()
    admission.check_connection(conn, directory)
    publication.assert_held()
    _need(catalog.active(conn))
    if writing:
        _need(conn.execute("PRAGMA query_only").fetchone()[0] == 0)


@contextmanager
def _write(conn):
    _transaction(conn, writing=True)
    conn.execute("SAVEPOINT operator_x_quota_write")
    try:
        yield
    except BaseException:
        conn.execute("ROLLBACK TO operator_x_quota_write")
        conn.execute("RELEASE operator_x_quota_write")
        raise
    else:
        conn.execute("RELEASE operator_x_quota_write")


def _objects(conn):
    return {row[0]: (row[1], row[2]) for row in conn.execute(
        "SELECT name,type,sql FROM main.sqlite_master WHERE name LIKE ? OR tbl_name LIKE ? LIMIT 32",
        (PREFIX + "%", PREFIX + "%"))}


def _schema(conn):
    objects = _objects(conn)
    _need(set(objects) == set(_DDL) | _AUTO_INDEXES)
    for name, sql in _DDL.items():
        kind = "table" if name in (STATE, ACCOUNTS, BUCKETS, ATTEMPTS) else (
            "index" if name in (PREFIX + "expiry", PREFIX + "subject") else "trigger")
        _need(objects[name] == (kind, sql))
    _need(all(objects[name] == ("index", None) for name in _AUTO_INDEXES))


def _marker(conn):
    rows = conn.execute("SELECT id,event_json,event_hash FROM main.audit_events WHERE event_type=? LIMIT 2",
        (INITIALIZED,)).fetchall()
    _need(len(rows) <= 1)
    return rows[0] if rows else None


def _ready(conn):
    _transaction(conn)
    return _retained_state(conn)


def _retained_state(conn):
    """Pure retained-row validator; does not grant runtime quota authority."""
    _need(conn.in_transaction)
    _schema(conn)
    rows = conn.execute(f"SELECT * FROM main.{STATE}").fetchall()
    _need(len(rows) == 1)
    state = dict(rows[0])
    marker = _marker(conn)
    _need(state["singleton"] == state["schema_version"] == 1 and marker is not None
        and _uuid(state["initialization_id"]) and marker[0] == state["initialization_id"]
        and marker[2] == state["initialization_hash"]
        and _integer(state["initialized_at_epoch_ms"]) and _integer(state["wall_highwater_ms"])
        and state["wall_highwater_ms"] >= state["initialized_at_epoch_ms"]
        and _load(marker[1]) in (
            {"schema": "catchplate.operatorXPostingQuotaStore/v1",
                "initialized_at_epoch_ms": state["initialized_at_epoch_ms"]},
            # Historical initialization is audit-hash-bound. New writers above
            # emit only Catchplate; do not rewrite an existing chain to rebrand it.
            {"schema": "serverware.operatorXPostingQuotaStore/v1",
                "initialized_at_epoch_ms": state["initialized_at_epoch_ms"]}))
    return state


@_closed
def require_ready(conn):
    """Query-only safe; never install, expire, repair, commit or observe HTTP."""
    _ready(conn)


def _audit(conn, event, values, actor_id=None):
    from catchplate import db
    return db.append_audit_event(conn, event_type="operator_x.quota." + event,
        actor_type="data_plane" if actor_id and event != "initialized" else "system", actor_id=actor_id, event=values)


@_closed
def initialize(conn, *, actor_id="startup"):
    """Reviewed startup migration only, in the caller's existing transaction.

    Existing objects/marker must validate; absence never repairs partial state.
    The old catalog must contain no already-limited X rule before first install.
    """
    with _write(conn):
        if _objects(conn):
            _ready(conn)
            return
        _need(_marker(conn) is None)
        _need(not any("daily_post_attempt_limit" in rule
            for rule in catalog.read_catalog(conn)["access_rules"]))
        now = _clock()
        for sql in _DDL.values():
            conn.execute(sql)
        event = _audit(conn, "initialized", {"schema": "catchplate.operatorXPostingQuotaStore/v1",
            "initialized_at_epoch_ms": now}, actor_id)
        conn.execute(f"INSERT INTO main.{STATE} VALUES(1,1,?,?,?,?)",
            (event["id"], event["event_hash"], now, now))
        _ready(conn)


def _binding(binding):
    _need(type(binding) is dict and set(binding) == BINDING_FIELDS)
    _need(all(type(binding[key]) is str and _SHA.fullmatch(binding[key]) for key in _DIGEST_FIELDS))
    _need(_uuid(binding["credential_id"]) and _integer(binding["credential_version"])
        and _integer(binding["expires_at_epoch_ms"]))
    for key in ("principal_id", "route_id"):
        value = binding[key]
        _need(type(value) is str and 1 <= len(value.encode("utf-8")) <= 512
            and value.strip() == value and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value))
    _need(len(_json(binding).encode("ascii")) <= 4096)


def _current(conn, binding, now):
    from catchplate import app, operator_catalog_x_oauth as accounts
    _binding(binding)
    row = conn.execute("SELECT id,kind,credential_version,metadata,lifecycle_status FROM main.credentials WHERE id=?",
        (binding["credential_id"],)).fetchone()
    _need(row is not None)
    core = dict(row)
    core["metadata"] = _load(core["metadata"])
    _need(core["credential_version"] == binding["credential_version"])
    selected = accounts.require_lease_binding(conn, principal_id=binding["principal_id"],
        route_id=binding["route_id"], credential_id=binding["credential_id"], core_credential=core)
    _need(app._credential_lease_metadata_sha256(app._credential_lease_public_metadata(core))
        == binding["credential_metadata_digest"])
    policy = conn.execute("SELECT policy_hash FROM main.operator_demo_policy WHERE singleton=1").fetchone()
    _need(policy is not None and policy[0] == binding["policy_hash"])
    retained = catalog.read_catalog(conn)
    rules = [r for r in retained["access_rules"] if r.get("route_id") == binding["route_id"]]
    applications = [a for a in retained["applications"] if a.get("principal_id") == binding["principal_id"]]
    _need(len(rules) == len(applications) == 1)
    maximum = rules[0].get("daily_post_attempt_limit")
    _need(type(maximum) is int and 1 <= maximum <= 1_000_000_000)
    subject = selected["provider_subject"]
    _need(type(subject) is str and _SUBJECT.fullmatch(subject))
    expiry = binding["expires_at_epoch_ms"]
    if not now < expiry:
        raise QuotaConflict()
    _need(expiry <= now + MAX_TTL_MS and expiry <= (now // DAY_MS + 1) * DAY_MS
        and expiry <= applications[0]["token_expires_at_epoch_ms"]
        and expiry <= core["metadata"]["expires_at_epoch_ms"])
    return subject, maximum


def _now(state):
    now = _clock()
    _need(now >= state["wall_highwater_ms"])
    return now


@_closed
def validate_current(conn, binding):
    """The final lease response may recheck scope without another reservation."""
    state = _ready(conn)
    _current(conn, binding, _now(state))


def _bucket_key(subject, day):
    return _digest({"provider": "x", "subject": subject, "operation": "tweets.write", "utc_day": day})


def _bucket(conn, subject, day):
    row = conn.execute(f"SELECT * FROM main.{BUCKETS} WHERE provider_subject=? AND utc_day=?",
        (subject, day)).fetchone()
    _need(row is not None)
    value = dict(row)
    _need(value["bucket_key"] == _bucket_key(subject, day)
        and _integer(value["claimed"], 0) and _integer(value["outstanding"], 0)
        and value["outstanding"] <= MAX_OUTSTANDING)
    # This index spans at most the bounded active reservations, not all claims.
    count = conn.execute(f"SELECT count(*) FROM main.{ATTEMPTS} WHERE bucket_key=? AND state='reserved'",
        (value["bucket_key"],)).fetchone()[0]
    _need(count == value["outstanding"])
    return value


def _account(conn, subject):
    row = conn.execute(f"SELECT * FROM main.{ACCOUNTS} WHERE provider_subject=?", (subject,)).fetchone()
    if row is None:
        # A removed anchor cannot turn existing attempts/counters into a virgin account.
        _need(conn.execute(f"SELECT 1 FROM main.{BUCKETS} WHERE provider_subject=? LIMIT 1", (subject,)).fetchone() is None
            and conn.execute(f"SELECT 1 FROM main.{ATTEMPTS} WHERE provider_subject=? LIMIT 1", (subject,)).fetchone() is None)
        return None
    account = dict(row)
    _need(_integer(account["last_day"], 0) and _integer(account["created_at_epoch_ms"]))
    _bucket(conn, subject, account["last_day"])
    return account


def _attempt(row):
    value = dict(row)
    binding = _load(value["binding_json"])
    _binding(binding)
    _need(_uuid(value["reservation_id"]) and value["attempt_nonce"] == binding["attempt_nonce"]
        and value["binding_json"] == _json(binding) and value["binding_digest"] == _digest(binding)
        and value["expires_at_epoch_ms"] == binding["expires_at_epoch_ms"]
        and _SUBJECT.fullmatch(value["provider_subject"])
        and value["utc_day"] == value["created_at_epoch_ms"] // DAY_MS
        and value["bucket_key"] == _bucket_key(value["provider_subject"], value["utc_day"])
        and _integer(value["created_at_epoch_ms"])
        and value["created_at_epoch_ms"] < value["expires_at_epoch_ms"] <= value["created_at_epoch_ms"] + MAX_TTL_MS
        and value["expires_at_epoch_ms"] <= (value["utc_day"] + 1) * DAY_MS
        and value["state"] in {"reserved", "claimed", "expired"})
    _need((_integer(value["claimed_at_epoch_ms"])
        and value["created_at_epoch_ms"] <= value["claimed_at_epoch_ms"] < value["expires_at_epoch_ms"])
        if value["state"] == "claimed" else value["claimed_at_epoch_ms"] is None)
    return value


def _expire(conn, bucket, now):
    rows = conn.execute(f"SELECT * FROM main.{ATTEMPTS} WHERE bucket_key=? AND state='reserved' "
        "AND expires_at_epoch_ms<=? ORDER BY expires_at_epoch_ms LIMIT ?",
        (bucket["bucket_key"], now, MAX_OUTSTANDING + 1)).fetchall()
    _need(len(rows) <= MAX_OUTSTANDING)
    for row in rows:
        value = _attempt(row)
        _need(conn.execute(f"UPDATE main.{ATTEMPTS} SET state='expired' WHERE reservation_id=? AND state='reserved'",
            (value["reservation_id"],)).rowcount == 1)
    if rows:
        conn.execute(f"UPDATE main.{BUCKETS} SET outstanding=outstanding-? WHERE bucket_key=?",
            (len(rows), bucket["bucket_key"]))
        _audit(conn, "expired", {"bucket_key": bucket["bucket_key"], "reservations": len(rows)})
    return _bucket(conn, bucket["provider_subject"], bucket["utc_day"])


def _receipt(attempt, *, claimed=False):
    result = {"schema": CLAIM_SCHEMA if claimed else RESERVATION_SCHEMA,
        **{key: attempt[key] for key in ("reservation_id", "bucket_key", "utc_day",
            "expires_at_epoch_ms", "binding_digest")}}
    if claimed:
        result["claimed_at_epoch_ms"] = attempt["claimed_at_epoch_ms"]
    return result


@_closed
def reserve(conn, binding):
    with _write(conn):
        state = _ready(conn)
        now = _now(state)
        subject, maximum = _current(conn, binding, now)
        day = now // DAY_MS
        if conn.execute(f"SELECT 1 FROM main.{ATTEMPTS} WHERE attempt_nonce=?", (binding["attempt_nonce"],)).fetchone():
            raise QuotaConflict()
        account = _account(conn, subject)
        if account is not None:
            _need(day >= account["last_day"])
            _expire(conn, _bucket(conn, subject, account["last_day"]), now)
        if account is None or day > account["last_day"]:
            _need(conn.execute(f"SELECT 1 FROM main.{BUCKETS} WHERE provider_subject=? AND utc_day=?", (subject, day)).fetchone() is None)
            conn.execute(f"INSERT INTO main.{BUCKETS} VALUES(?,?,?,0,0)", (_bucket_key(subject, day), subject, day))
            if account is None:
                conn.execute(f"INSERT INTO main.{ACCOUNTS} VALUES(?,?,?)", (subject, day, now))
            else:
                conn.execute(f"UPDATE main.{ACCOUNTS} SET last_day=? WHERE provider_subject=?", (day, subject))
        bucket = _bucket(conn, subject, day)
        if bucket["claimed"] + bucket["outstanding"] >= maximum:
            raise QuotaExceeded()
        _need(bucket["outstanding"] < MAX_OUTSTANDING)
        identifier = str(uuid.uuid4())
        conn.execute(f"INSERT INTO main.{ATTEMPTS} VALUES(?,?,?,?,?,?,?,'reserved',?,?,NULL)",
            (identifier, binding["attempt_nonce"], bucket["bucket_key"], subject, day,
                _json(binding), _digest(binding), now, binding["expires_at_epoch_ms"]))
        conn.execute(f"UPDATE main.{BUCKETS} SET outstanding=outstanding+1 WHERE bucket_key=?", (bucket["bucket_key"],))
        conn.execute(f"UPDATE main.{STATE} SET wall_highwater_ms=? WHERE singleton=1", (now,))
        attempt = _attempt(conn.execute(f"SELECT * FROM main.{ATTEMPTS} WHERE reservation_id=?", (identifier,)).fetchone())
        receipt = _receipt(attempt)
        _audit(conn, "reserved", {**receipt, "binding": dict(binding)}, binding["principal_id"])
        return receipt


@_closed
def claim(conn, binding, reservation_id):
    with _write(conn):
        state = _ready(conn)
        now = _now(state)
        subject, maximum = _current(conn, binding, now)
        _need(_uuid(reservation_id))
        row = conn.execute(f"SELECT * FROM main.{ATTEMPTS} WHERE reservation_id=?", (reservation_id,)).fetchone()
        _need(row is not None)
        attempt = _attempt(row)
        _need(attempt["binding_json"] == _json(binding) and attempt["provider_subject"] == subject)
        if attempt["state"] != "reserved" or attempt["utc_day"] != now // DAY_MS:
            raise QuotaConflict()
        _need(_account(conn, subject) is not None)
        bucket = _expire(conn, _bucket(conn, subject, attempt["utc_day"]), now)
        if bucket["claimed"] + bucket["outstanding"] > maximum:
            raise QuotaExceeded()
        _need(bucket["outstanding"] > 0 and bucket["claimed"] < MAX_INTEGER)
        _need(conn.execute(f"UPDATE main.{ATTEMPTS} SET state='claimed',claimed_at_epoch_ms=? "
            "WHERE reservation_id=? AND state='reserved'", (now, reservation_id)).rowcount == 1)
        conn.execute(f"UPDATE main.{BUCKETS} SET claimed=claimed+1,outstanding=outstanding-1 WHERE bucket_key=?",
            (bucket["bucket_key"],))
        conn.execute(f"UPDATE main.{STATE} SET wall_highwater_ms=? WHERE singleton=1", (now,))
        attempt["claimed_at_epoch_ms"] = now
        receipt = _receipt(attempt, claimed=True)
        _audit(conn, "claimed", {**receipt, "binding": dict(binding)}, binding["principal_id"])
        return receipt


@_closed
def usage(conn, credential_id):
    """Metadata-only current-day counts; logical expiry never writes on GET."""
    from catchplate import operator_catalog_x_oauth as accounts
    state = _ready(conn)
    _need(_uuid(credential_id))
    records = [r for r in catalog.read_catalog(conn)["credentials"] if r["id"] == credential_id]
    _need(len(records) == 1)
    accounts.validate_identity(records[0])
    subject = records[0]["provider_subject"]
    now = _now(state)
    day = now // DAY_MS
    account = _account(conn, subject)
    claimed = outstanding = 0
    if account is not None:
        _need(day >= account["last_day"])
        if account["last_day"] == day:
            bucket = _bucket(conn, subject, day)
            claimed = bucket["claimed"]
            outstanding = conn.execute(f"SELECT count(*) FROM main.{ATTEMPTS} "
                "WHERE bucket_key=? AND state='reserved' AND expires_at_epoch_ms>?", (bucket["bucket_key"], now)).fetchone()[0]
    return {"schema": "catchplate.operatorXPostingQuotaUsage/v1", "utc_day": day,
        "claimed_attempts": claimed, "outstanding_reservations": outstanding,
        "resets_at_epoch_ms": (day + 1) * DAY_MS}
