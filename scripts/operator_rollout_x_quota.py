"""Exact additive quota initialization on disposable rollout database copies.

No application imports, initialization, key access or namespace exclusions.
The schema pin covers all SQL text, including indexes and immutable triggers.
The caller still compares every existing schema object, typed row and audit
prefix; this helper admits only the explicitly selected initialization delta.
"""
from datetime import datetime, timezone
import hashlib
import json
import re
import uuid

PREFIX = "operator_x_quota_"
TABLES = frozenset(PREFIX + name for name in ("state", "accounts", "buckets", "attempts"))
USAGE_TABLES = TABLES - {PREFIX + "state"}
OBJECTS = (TABLES | {PREFIX + name for name in ("expiry", "subject")}
    | {table + suffix for table in TABLES for suffix in ("_no_delete", "_update")}
    | {"sqlite_autoindex_" + PREFIX + name for name in (
        "accounts_1", "buckets_1", "buckets_2", "attempts_1", "attempts_2")})
# Reviewed actual SQLite projection of operator_x_quota's 14 CREATE statements
# plus its five automatic indexes. Source parity is independently tested.
SCHEMA_SHA256 = "2d977d0783bb11f91ed8c58127fba77b9eb6157b3df86d84b47eaf0fa8f6e45a"
EVENT = "operator_x.quota.initialized"
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_AUDIT_FIELDS = frozenset({"rowid", "id", "event_type", "actor_type", "actor_id", "event_json",
    "encrypted_canonical_event_json", "storage_format_version", "prev_event_hash", "event_hash", "created_at"})


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def schema_transition(before, after, phase, require):
    require(phase in {"first", "retained"}, "x_quota_options")
    added = [row for row in after if row[1] in OBJECTS]
    require(len(added) == len(OBJECTS) and {row[1] for row in added} == OBJECTS
        and digest(added) == SCHEMA_SHA256, "x_quota_schema")
    require(not any(row[1] not in OBJECTS and any(value.lower().startswith(PREFIX)
        for value in row[1:3]) for row in after), "x_quota_schema")
    if phase == "first":
        require(not any(value.lower().startswith(PREFIX) for row in before for value in row[1:3]),
            "x_quota_not_fresh")
        # Only the exact reviewed roster is subtracted, never a prefix.
        require(before == [row for row in after if row[1] not in OBJECTS], "database_schema_changed")
    else:
        require(before == after, "database_schema_changed")
    return TABLES if phase == "first" else frozenset()


def _query(connection, statement, values=()):
    cursor = connection.execute(statement, values)
    columns = [item[0] for item in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def initialization(before, after, phase, prior_count, current_count, require):
    states = _query(after, "SELECT * FROM operator_x_quota_state LIMIT 2")
    require(len(states) == 1, "x_quota_state")
    state = states[0]
    require(set(state) == {"singleton", "schema_version", "initialization_id", "initialization_hash",
        "initialized_at_epoch_ms", "wall_highwater_ms"}, "x_quota_state")
    for key in ("singleton", "schema_version", "initialized_at_epoch_ms", "wall_highwater_ms"):
        require(type(state[key]) is int and 1 <= state[key] <= 9_007_199_254_740_991, "x_quota_state")
    require(state["singleton"] == state["schema_version"] == 1
        and state["initialized_at_epoch_ms"] == state["wall_highwater_ms"], "x_quota_state")
    for table in sorted(USAGE_TABLES):
        require(after.execute('SELECT 1 FROM "' + table + '" LIMIT 1').fetchone() is None,
            "x_quota_usage_not_empty", table)
    markers = _query(after, "SELECT rowid,* FROM audit_events WHERE event_type=? LIMIT 2", (EVENT,))
    require(len(markers) == 1 and set(markers[0]) == _AUDIT_FIELDS, "x_quota_initialization_audit")
    marker = markers[0]
    try:
        identifier = uuid.UUID(marker["id"])
        stamp = datetime.fromisoformat(marker["created_at"])
        valid = (str(identifier) == marker["id"] and identifier.version == 4
            and stamp.tzinfo == timezone.utc and stamp.isoformat() == marker["created_at"])
    except (ValueError, TypeError, AttributeError):
        valid = False
    require(valid and type(marker["rowid"]) is int and marker["rowid"] > 0
        and marker["actor_type"] == "system" and marker["actor_id"] == "startup"
        and marker["encrypted_canonical_event_json"] is None
        and type(marker["storage_format_version"]) is int and marker["storage_format_version"] == 2,
        "x_quota_initialization_audit")
    body = {"schema": "serverware.operatorXPostingQuotaStore/v1",
        "initialized_at_epoch_ms": state["initialized_at_epoch_ms"]}
    require(marker["event_json"] == canonical(body)
        and type(marker["event_hash"]) is str and _SHA.fullmatch(marker["event_hash"])
        and state["initialization_id"] == marker["id"]
        and state["initialization_hash"] == marker["event_hash"], "x_quota_initialization_audit")
    hashed = {key: marker[key] for key in ("id", "event_type", "actor_type", "actor_id",
        "event_json", "prev_event_hash", "created_at")}
    require(marker["event_hash"] == "sha256:" + digest(hashed), "x_quota_audit_hash")
    preceding = after.execute("SELECT event_hash FROM audit_events WHERE rowid<? ORDER BY rowid DESC LIMIT 1",
        (marker["rowid"],)).fetchone()
    require(marker["prev_event_hash"] == (preceding[0] if preceding else None), "x_quota_audit_chain")
    if phase == "first":
        require(before.execute("SELECT 1 FROM audit_events WHERE event_type=? LIMIT 1", (EVENT,)).fetchone() is None
            and current_count == prior_count + 1, "x_quota_audit_delta")
        last = after.execute("SELECT rowid FROM audit_events ORDER BY rowid DESC LIMIT 1").fetchone()
        require(last == (marker["rowid"],), "x_quota_audit_delta")
    else:
        require(current_count == prior_count, "x_quota_audit_delta")
    return {"transition": phase, "schema_sha256": SCHEMA_SHA256,
        "added_schema_objects": sorted(OBJECTS) if phase == "first" else [],
        "state_sha256": digest(state), "empty_usage_tables": sorted(USAGE_TABLES),
        "initialization_event_id": marker["id"], "initialization_event_hash": marker["event_hash"],
        "audit_append_count": 1 if phase == "first" else 0, "audit_chain_extension_verified": True}
