"""Bounded, read-only observations, not account health or audit-chain proof.

Read the global durable tail in the caller's catalog snapshot. No credential
material, provider transport, audit verification, or mutation helper is used.
Recorded release evidence is not proof that a client received the response.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import re
import uuid

SCHEMA = "serverware.operatorAccountActivity/v1"
ROW_LIMIT = 256
EVENT_BYTE_LIMIT = 16_384
BYTE_LIMIT = 2_097_152
_MAX_RESOURCES = 1024
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_START = "data_plane.credential.release_started"
_RELEASE = "data_plane.response.released"
_BLOCK = "data_plane.response.blocked"
_REFRESH = "credential.oauth_refreshed"
_FAILURE = "credential.oauth_refresh_failed"
_EVENTS = {_START, _RELEASE, _BLOCK, _REFRESH, _FAILURE}
_JOIN_FIELDS = ("credential_ref", "credential_version", "principal_id", "route_id",
                "policy_hash", "request_digest", "operation_digest", "method")


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 9_007_199_254_740_991


def _uuid(value):
    return isinstance(value, str) and len(value) == 36 and str(uuid.UUID(value)) == value


def _text(value, limit):
    return (isinstance(value, str) and 0 < len(value) <= limit
            and value.isascii() and all(32 <= ord(char) <= 126 for char in value))


def _hash(value):
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _event_id(value):
    return _hash(value) or _uuid(value)


def _window():
    return {"row_limit": ROW_LIMIT, "event_byte_limit": EVENT_BYTE_LIMIT,
            "byte_limit": BYTE_LIMIT, "rows_scanned": 0, "bytes_read": 0,
            "has_older_rows": False, "byte_budget_exhausted": False,
            "oversized_events": 0, "invalid_events": 0,
            "unmatched_responses": 0, "incomplete": False}


def _result(now, *, available=False):
    window = _window()
    window["incomplete"] = not available
    return {"schema": SCHEMA, "status": "available" if available else "unavailable",
            "observed_at_epoch_ms": now, "chain_verification": "not_checked",
            "window": window, "accounts": []}


def _indexes(catalog):
    indexes = {}
    for collection in ("credentials", "applications", "access_rules"):
        rows = catalog[collection]
        if not isinstance(rows, list) or len(rows) > _MAX_RESOURCES:
            raise ValueError("catalog evidence identity unavailable")
        index = {}
        for row in rows:
            if not isinstance(row, dict) or not _uuid(row.get("id")) or row["id"] in index:
                raise ValueError("catalog evidence identity unavailable")
            index[row["id"]] = row
        indexes[collection] = index
    credentials, apps, rules = (indexes[key] for key in indexes)
    if any(row.get("auth_type") not in {"bearer", "header", "google_oauth"}
           for row in credentials.values()):
        raise ValueError("catalog evidence identity unavailable")
    principals = [app.get("principal_id") for app in apps.values()]
    if any(not _text(value, 256) for value in principals) or len(set(principals)) != len(principals):
        raise ValueError("catalog evidence identity unavailable")
    routes = {}
    for rule in rules.values():
        route = rule.get("route_id")
        if (not _text(route, 256) or route in routes
                or rule.get("credential_id") not in credentials
                or rule.get("application_id") not in apps):
            raise ValueError("catalog evidence identity unavailable")
        routes[route] = rule
    return credentials, apps, routes


def _recorded_at(value, now):
    if not _text(value, 64):
        raise ValueError("audit timestamp unavailable")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("audit timestamp unavailable")
    delta = parsed.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    stamp = delta.days * 86_400_000 + delta.seconds * 1000 + delta.microseconds // 1000
    if not 0 <= stamp <= now:
        raise ValueError("audit timestamp unavailable")
    return stamp


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("ambiguous audit JSON")
        result[key] = value
    return result


def _constant(_value):
    raise ValueError("nonfinite audit JSON")


def _parse(raw):
    event = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                       parse_constant=_constant)
    if not isinstance(event, dict):
        raise ValueError("audit event is not an object")
    pending, visited = [(event, 0)], 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if depth > 32 or visited > 4096:
            raise ValueError("audit structure exceeds observation bounds")
        if isinstance(value, dict):
            for key, child in value.items():
                key.encode("utf-8", "strict")
                pending.append((child, depth + 1))
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            value.encode("utf-8", "strict")
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("nonfinite audit JSON")
    return event


def _read(conn, window, now):
    # Every metadata value is bounded in SQL, before it enters Python. JSON is
    # fetched separately: at most 16 KiB per event, 2 MiB total. Metadata itself
    # has a separate fixed <=528-byte-per-row bound (plus numeric columns).
    columns = [("id", 80), ("event_type", 96), ("actor_type", 32),
               ("actor_id", 256), ("created_at", 64)]
    bounded = [f"CASE WHEN typeof({name})='text' AND "
               f"length(CAST({name} AS BLOB)) BETWEEN 1 AND {limit} "
               f"THEN {name} ELSE NULL END" for name, limit in columns]
    query = ("SELECT rowid," + ",".join(bounded)
             + ",typeof(event_json),length(CAST(event_json AS BLOB)) "
             + "FROM audit_events ORDER BY rowid DESC LIMIT ?")
    metadata = conn.execute(query, (ROW_LIMIT + 1,)).fetchall()
    window["has_older_rows"] = len(metadata) > ROW_LIMIT
    window["rows_scanned"] = min(len(metadata), ROW_LIMIT)
    events = []
    for row in metadata[:ROW_LIMIT]:
        rowid, identifier, kind, actor_type, actor_id, created, storage_type, size = row
        try:
            if not _event_id(identifier) or not _text(kind, 96) or not _text(actor_type, 32):
                raise ValueError("audit metadata unavailable")
            stamp = _recorded_at(created, now)
            if kind not in _EVENTS:
                continue
            if not _text(actor_id, 256) or storage_type != "text" or not _integer(size):
                raise ValueError("audit metadata unavailable")
            if size > EVENT_BYTE_LIMIT:
                window["oversized_events"] += 1
                continue
            if window["bytes_read"] + size > BYTE_LIMIT:
                window["byte_budget_exhausted"] = True
                break
            payload = conn.execute(
                "SELECT CAST(event_json AS BLOB) FROM audit_events WHERE rowid=? "
                "AND typeof(event_json)='text' AND length(CAST(event_json AS BLOB))<=?",
                (rowid, EVENT_BYTE_LIMIT)).fetchone()
            if payload is None or not isinstance(payload[0], bytes) or len(payload[0]) != size:
                raise ValueError("audit payload unavailable")
            window["bytes_read"] += size
            event = _parse(payload[0])
            events.append((rowid, identifier, kind, actor_type, actor_id, stamp, event))
        except (ValueError, TypeError, OverflowError, RecursionError):
            window["invalid_events"] += 1
    return events


def _observation(row, event):
    return {"event_id": row[1], "recorded_at_epoch_ms": row[5],
            "credential_version": event["credential_version"]}


def _response_identity(event):
    return (event.get("component") == "serverware-decision-gate-rs"
            and _uuid(event.get("credential_ref"))
            and _integer(event.get("credential_version"), 1)
            and _text(event.get("principal_id"), 256)
            and _text(event.get("route_id"), 256)
            and all(_hash(event.get(key)) for key in
                    ("policy_hash", "request_digest", "operation_digest"))
            and event.get("method") in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})


def _project(conn, catalog, now):
    credentials, apps, routes = _indexes(catalog)
    result = _result(now, available=True)
    accounts = {identifier: {"credential_id": identifier, "last_successful_response": None,
                "last_refresh_success": None, "last_refresh_failure": None,
                "last_refresh_outcome": "unobserved"} for identifier in credentials}
    window = result["window"]
    rows = _read(conn, window, now)
    # Chronological receiver timestamps, with insertion order breaking ties.
    # These are observations of immutable retained IDs, including revoked rows.
    rows.sort(key=lambda row: (row[5], row[0]), reverse=True)
    attempts = {}
    for row in rows:
        _, _, kind, actor_type, actor_id, _, event = row
        if kind in {_REFRESH, _FAILURE}:
            identifier = event.get("credential_id")
            credential = credentials.get(identifier) if isinstance(identifier, str) else None
            valid = (actor_type == "system" and actor_id == "oauth-refresh"
                     and event.get("provider") == "google"
                     and _integer(event.get("credential_version"), 1))
            if kind == _REFRESH:
                previous = event.get("previous_credential_version")
                valid = (valid and _integer(previous, 1)
                         and previous < event["credential_version"])
            if not valid:
                window["invalid_events"] += 1
            elif credential is not None and credential["auth_type"] == "google_oauth":
                account = accounts[identifier]
                field = "last_refresh_success" if kind == _REFRESH else "last_refresh_failure"
                if account[field] is None:
                    account[field] = _observation(row, event)
                if account["last_refresh_outcome"] == "unobserved":
                    account["last_refresh_outcome"] = "success" if kind == _REFRESH else "failure"
            continue
        attempt = event.get("attempt_id")
        if actor_type != "data-plane" or not _hash(attempt):
            window["invalid_events"] += 1
            if kind == _RELEASE:
                window["unmatched_responses"] += 1
            continue
        # Keep malformed/blocked members too: they cannot disappear to make a
        # convenient pair out of another start and release for this attempt.
        attempts.setdefault((actor_id, attempt), []).append(row)

    response_ranks = {}
    for (_, attempt), members in attempts.items():
        starts = [row for row in members if row[2] == _START]
        releases = [row for row in members if row[2] == _RELEASE]
        if not releases:
            continue
        if len(starts) != 1 or len(releases) != 1 or len(members) != 2:
            window["unmatched_responses"] += len(releases)
            continue
        start, terminal = starts[0][6], releases[0][6]
        try:
            # The gate requires the durable release-start ACK before dispatch.
            # Receiver clocks may regress, but the insertion order cannot.
            valid = (starts[0][0] < releases[0][0]
                     and all(event.get("flow_id") == attempt and _response_identity(event)
                         for event in (start, terminal))
                     and start.get("outcome") == "release_started"
                     and terminal.get("outcome") == "released"
                     and all(start.get(key) == terminal.get(key) for key in _JOIN_FIELDS)
                     and _integer(terminal.get("upstream_status"), 100)
                     and terminal["upstream_status"] <= 599
                     and _hash(terminal.get("response_body_sha256"))
                     and _integer(terminal.get("response_body_bytes")))
        except (ValueError, TypeError):
            valid = False
        rule = routes.get(terminal.get("route_id")) if isinstance(terminal.get("route_id"), str) else None
        if (not valid or rule is None or rule["credential_id"] != terminal.get("credential_ref")
                or apps[rule["application_id"]]["principal_id"] != terminal.get("principal_id")):
            window["unmatched_responses"] += 1
            continue
        if not 200 <= terminal["upstream_status"] < 300:
            continue
        account = accounts[rule["credential_id"]]
        evidence = _observation(releases[0], terminal)
        evidence.update(application_id=rule["application_id"], rule_id=rule["id"])
        # Timestamp ordering may differ from insertion order after a receiver
        # clock adjustment. Rank the terminal observation explicitly.
        rank = (releases[0][5], releases[0][0])
        if rank > response_ranks.get(rule["credential_id"], (-1, -1)):
            account["last_successful_response"] = evidence
            response_ranks[rule["credential_id"]] = rank
    window["incomplete"] = any(window[key] for key in (
        "has_older_rows", "byte_budget_exhausted", "oversized_events", "invalid_events", "unmatched_responses"))
    result["accounts"] = list(accounts.values())
    return result


def project(conn, catalog, *, observed_at_epoch_ms):
    """Return allowlisted facts, or unavailable; never change the read snapshot.

    The caller must validate catalog bindings first. This optional view does not
    weaken those guards. No exception details or audit payloads are returned.
    """
    now = observed_at_epoch_ms if _integer(observed_at_epoch_ms) else 0
    try:
        if not _integer(observed_at_epoch_ms) or not conn.in_transaction:
            raise ValueError("audit read snapshot unavailable")
        return _project(conn, catalog, now)
    except Exception:
        return _result(now)
