"""Explicit host-trusted, exact-request approvals for the operator workspace.

The host administrator is trusted. These rows are not native, measured-writer,
WebAuthn or TEE evidence. Existing ordinary SQLite tables own one transaction
for every decision/claim and its audit; no provider request is made here.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import sqlite3
import time
import uuid

FLAG = "SERVERWARE_HOST_TRUSTED_APPROVALS_ENABLED"
REQUEST_VERSION = "serverware.hostTrustedApprovalClaimRequest/v1"
RESPONSE_VERSION = "serverware.hostTrustedApprovalClaimResponse/v1"
CLAIM_PATH = "/api/data-plane/host-trusted-approvals/claim"
PREFIX = "/api/operator-demo/approvals"
UUID_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
POLICY_CONSTRAINT = {"type": "hostTrustedApproval", "schema": "serverware.hostTrustedApprovalPolicy/v1",
    "pendingTtlSeconds": 300, "approvalTtlSeconds": 60}
POLICY_SCHEMA = "serverware.hostTrustedApprovalReviewer/v1"
MAX_REQUEST_BYTES = 65536
_FIELDS = frozenset({"apiVersion", "principalId", "routeId", "credentialId", "credentialVersion",
    "policyHash", "requestDigest", "operationDigest", "attemptId", "canonicalRequest"})
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PUBLIC = ("id", "status", "route_id", "method", "url", "requested_at", "expires_at", "approved_until",
    "principal_id", "credential_id", "credential_version", "policy_hash", "request_digest", "operation_digest",
    "approved_by", "decision_note")


class ApprovalConflict(ValueError):
    pass


class ApprovalNotFound(ValueError):
    pass


def owns_post(path):
    return type(path) is str and (path == CLAIM_PATH or re.fullmatch(
        re.escape(PREFIX) + "/" + UUID_PATTERN + "/(?:review|decision)", path) is not None)


def _need(value):
    if not value:
        raise ApprovalConflict("Host-trusted approval changed or is unavailable")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def _text(value, maximum=512):
    _need(type(value) is str and 0 < len(value.encode("utf-8")) <= maximum
        and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _clock():
    return time.time_ns() // 1_000_000


def _stamp(value):
    return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat()


def _epoch(value):
    parsed = datetime.fromisoformat(value)
    _need(parsed.tzinfo is not None)
    return int(parsed.timestamp() * 1000)


def _profile():
    from serverware import config, db, operator_demo
    _need(operator_demo.active() and not db.metadata_uses_postgres()
        and config.GRANT_STORE_BACKEND == "sqlite" and not config.ATOMIC_RELEASE_AUTHORIZATION_ENABLED)
    return db, config


def enabled():
    try:
        _profile()
        return os.environ.get(FLAG) == "1"
    except Exception:
        return False


def available():
    """A fresh bounded gate observation, never while holding publication locks."""
    try:
        if not enabled():
            return False
        from serverware import operator_demo_store as operator
        observed, current = operator.loaded_gate_status(), operator.get_policy_high_water()
        return (type(observed) is dict and type(current) is dict
            and observed.get("policy_hash") == current.get("policy_hash")
            and observed.get("host_trusted_approvals") == {
                "schema": "serverware.hostTrustedApprovalRuntime/v1", "enabled": True,
                "claim_request_version": REQUEST_VERSION, "claim_response_version": RESPONSE_VERSION})
    except Exception:
        return False


def capabilities(identity):
    from serverware import config
    actor = identity.user_id == config.ADMIN_USER_ID and identity.has_any_role({"admin"})
    ready = actor and identity.auth_method == "admin-token-header" and available()
    return {"schema": "serverware.approvalCapabilities/v2", "mode": "host_trusted_v1",
        "can_list": actor, "can_review": ready, "can_decide": ready,
        "reason": None if ready else "host_trusted_approvals_unavailable" if actor else "role_required"}


def validate_claim(value):
    _need(type(value) is dict and set(value) == _FIELDS and value["apiVersion"] == REQUEST_VERSION
        and len(canonical(value).encode("ascii")) <= MAX_REQUEST_BYTES)
    for name in ("principalId", "routeId", "credentialId"):
        _text(value[name], 256)
    for name in ("policyHash", "requestDigest", "operationDigest", "attemptId"):
        _need(type(value[name]) is str and _SHA.fullmatch(value[name]))
    _need(type(value["credentialVersion"]) is int and 1 <= value["credentialVersion"] <= 2**53 - 1)
    original = value["canonicalRequest"]
    _need(type(original) is dict and set(original) == {"v", "principal", "client_ip", "route_id",
        "credential_ref", "credential_version", "policy_hash", "request", "operation"})
    _need(type(original["v"]) is int and original["v"] in (1, 2, 3)
        and original["principal"] == value["principalId"] and original["route_id"] == value["routeId"]
        and original["credential_ref"] == value["credentialId"]
        and original["credential_version"] == str(value["credentialVersion"])
        and original["policy_hash"] == value["policyHash"]
        and (original["client_ip"] is None or type(original["client_ip"]) is str and len(original["client_ip"]) <= 64)
        and type(original["operation"]) is dict)
    request = original["request"]
    fields = {"method", "scheme", "authority", "path", "query", "headers", "body_sha256"}
    if original["v"] >= 2:
        fields.add("discard_headers")
    if original["v"] == 3:
        fields.update(("query_mode", "query_wire"))
    _need(type(request) is dict and set(request) == fields and request["scheme"] == "https")
    _need(type(request["method"]) is str and re.fullmatch(r"[A-Z]{1,16}", request["method"]))
    _text(request["authority"], 512)
    _text(request["path"], 8192)
    _need(request["path"].startswith("/") and "#" not in request["path"] and "?" not in request["path"]
        and type(request["body_sha256"]) is str and _SHA.fullmatch(request["body_sha256"]))
    _need(type(request["headers"]) is dict and len(request["headers"]) <= 64)
    for key, item in request["headers"].items():
        _text(key, 128)
        _need(key == key.lower() and type(item) is str and len(item.encode("utf-8")) <= 8192
            and not any(c in item for c in "\r\n\0"))
    _need(type(request["query"]) is list and len(request["query"]) <= 128)
    for pair in request["query"]:
        _need(type(pair) is list and len(pair) == 2
            and all(type(item) is str and len(item.encode("utf-8")) <= 8192 for item in pair))
    if original["v"] >= 2:
        _need(type(request["discard_headers"]) is list and len(request["discard_headers"]) <= 64
            and all(type(item) is str and re.fullmatch(r"[a-z0-9-]{1,128}", item)
                for item in request["discard_headers"]))
    if original["v"] == 3:
        _text(request["query_mode"], 128)
        _need(request["query_wire"] is None or type(request["query_wire"]) is str
            and len(request["query_wire"].encode("utf-8")) <= 16384)
    _need(digest(original) == value["requestDigest"]
        and digest({key: item for key, item in original.items() if key not in {"v", "client_ip"}})
            == value["operationDigest"])
    return value


def _policy(reviewer):
    return {"schema": POLICY_SCHEMA, "assurance": "host-trusted", "reviewerId": reviewer,
        "maxUses": 1, "pendingTtlSeconds": 300, "approvalTtlSeconds": 60}


def _current(conn, wire, now):
    """Current signed policy and current catalog, inside the same write lock."""
    from serverware import operator_catalog_schema as catalog, policy_bundle
    snapshot = policy_bundle.get_policy_snapshot()
    retained = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
    _need(snapshot is not None and retained is not None
        and snapshot.hash == retained["policy_hash"] == wire["policyHash"])
    routes = [item for item in snapshot.routes if item.id == wire["routeId"]]
    _need(len(routes) == 1)
    route, request = routes[0], wire["canonicalRequest"]["request"]
    marker = [item for item in route.constraints if item.get("type") == "hostTrustedApproval"]
    authority = route.host + (":" + str(route.port) if route.port != 443 else "")
    _need(marker == [POLICY_CONSTRAINT] and not route.jit
        and wire["principalId"] in route.principals and route.credential_ref == wire["credentialId"]
        and request["scheme"] == route.scheme and request["authority"] == authority
        and request["method"] in route.methods and route.match_path(request["path"]) is not None)
    records = catalog.read_catalog(conn)
    rules = [row for row in records["access_rules"] if row["status"] == "active"
        and (route.id == "operator." + row["id"] or route.id.startswith("operator." + row["id"] + "."))]
    _need(len(rules) == 1)
    rule = rules[0]
    _need(rule.get("approval_mode") == "host_review_v1" and rule["credential_id"] == wire["credentialId"])
    applications = [row for row in records["applications"] if row["id"] == rule["application_id"]]
    credentials = [row for row in records["credentials"] if row["id"] == wire["credentialId"]]
    _need(len(applications) == len(credentials) == 1 and applications[0]["status"] == credentials[0]["status"] == "active"
        and applications[0]["principal_id"] == wire["principalId"]
        and applications[0]["token_expires_at_epoch_ms"] > now)
    credential = conn.execute("SELECT credential_version,lifecycle_status FROM credentials WHERE id=?",
        (wire["credentialId"],)).fetchone()
    _need(credential is not None and credential["credential_version"] == wire["credentialVersion"]
        and credential["lifecycle_status"] == "active")


@contextmanager
def _transaction(*, write):
    db, config = _profile()
    if write:
        _need(enabled())
    with db.metadata_connection() as conn:
        _need(type(conn) is sqlite3.Connection)
        conn.execute("PRAGMA busy_timeout=1000")
        conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        yield conn, db, config.ADMIN_USER_ID, _clock()


def _owned(row, reviewer):
    _need(row is not None)
    row = dict(row)
    expected = _policy(reviewer)
    _need(row["approver_policy_json"] == canonical(expected)
        and row["approver_policy_digest"] == digest(expected)
        and not any(str(row.get(name) or "").lstrip().lower().startswith("native-jit")
            for name in ("url", "canonical_request", "redacted_display")))
    return row


def _find(conn, identifier, reviewer):
    try:
        _need(type(identifier) is str and str(uuid.UUID(identifier)) == identifier)
    except (ValueError, AttributeError):
        raise ApprovalNotFound() from None
    row = conn.execute("SELECT * FROM approval_requests WHERE id=?", (identifier,)).fetchone()
    if row is None:
        raise ApprovalNotFound()
    return _owned(row, reviewer)


def _wire(row, db):
    original = json.loads(db._decrypt_approval_json(row["canonical_request"]))
    return validate_claim({"apiVersion": REQUEST_VERSION, "canonicalRequest": original,
        "principalId": row["principal_id"], "routeId": row["route_id"], "credentialId": row["credential_id"],
        "credentialVersion": row["credential_version"], "policyHash": row["policy_hash"],
        "requestDigest": row["request_digest"], "operationDigest": row["operation_digest"],
        "attemptId": "sha256:" + "0" * 64})


def _document(wire):
    request = wire["canonicalRequest"]["request"]
    sensitive = re.compile(r"token|secret|password|authorization|cookie|api.?key|credential", re.I)
    return {"method": request["method"], "url": "https://" + request["authority"] + request["path"],
        "principal_id": wire["principalId"], "route_id": wire["routeId"], "credential_id": wire["credentialId"],
        "credential_version": wire["credentialVersion"], "policy_hash": wire["policyHash"],
        "request_digest": wire["requestDigest"], "operation_digest": wire["operationDigest"],
        "headers": {key: value if key in {"accept", "content-type"} else "[redacted]"
            for key, value in request["headers"].items()},
        "query": [[key, "[redacted]" if sensitive.search(key) else value] for key, value in request["query"]],
        "body_sha256": request["body_sha256"], "operation": wire["canonicalRequest"]["operation"]}


def _review_digest(row, document):
    return digest({"schema": "serverware.hostTrustedApprovalReview/v1", "approvalId": row["id"],
        "expiresAt": row["expires_at"], "document": document})


def _public(conn, row, reviewer, now, db):
    result = {name: row.get(name) for name in _PUBLIC}
    document = json.loads(db._decrypt_approval_json(row["redacted_display"]))
    _need(db._approval_url_commitment(document["url"]) == row["url"])
    result["url"] = document["url"]
    grant = conn.execute("SELECT consumed_at FROM approval_grants WHERE approval_request_id=?", (row["id"],)).fetchone()
    result.update(assurance="host-trusted", reviewer_id=reviewer,
        consumed_at=grant["consumed_at"] if grant is not None else None)
    if result["status"] in {"pending", "approved"} and now >= _epoch(
            result["approved_until"] if result["status"] == "approved" else result["expires_at"]):
        result["status"] = "expired"
    return result


def _audit(db, conn, event, row, actor, **extra):
    db.append_audit_event(conn, event_type="operator.host_approval." + event,
        actor_type="proxy" if event in {"requested", "claimed"} else "admin", actor_id=actor,
        event={"assurance": "host-trusted", "approval_request_id": row["id"],
            "principal_id": row["principal_id"], "route_id": row["route_id"],
            "credential_id": row["credential_id"], "credential_version": row["credential_version"],
            "policy_hash": row["policy_hash"], "request_digest": row["request_digest"],
            "operation_digest": row["operation_digest"], **extra})


def list_pending(actor):
    with _transaction(write=False) as (conn, db, reviewer, now):
        _need(actor == reviewer)
        rows = conn.execute("SELECT * FROM approval_requests WHERE status='pending' AND approver_policy_json=? "
            "AND expires_at>? ORDER BY requested_at DESC LIMIT 100", (canonical(_policy(reviewer)), _stamp(now))).fetchall()
        return [_public(conn, _owned(row, reviewer), reviewer, now, db) for row in rows]


def status(identifier, actor):
    with _transaction(write=False) as (conn, db, reviewer, now):
        _need(actor == reviewer)
        return _public(conn, _find(conn, identifier, reviewer), reviewer, now, db)


def review(identifier, actor):
    with _transaction(write=True) as (conn, db, reviewer, now):
        _need(actor == reviewer)
        row = _find(conn, identifier, reviewer)
        _need(row["status"] == "pending" and now < _epoch(row["expires_at"]))
        wire = _wire(row, db)
        _current(conn, wire, now)
        document = _document(wire)
        review_hash, receipt = _review_digest(row, document), str(uuid.uuid4())
        expiry = min(_epoch(row["expires_at"]), now + 120_000)
        _need(conn.execute("SELECT COUNT(*) FROM approval_review_receipts WHERE used_at IS NULL AND expires_at>?",
            (_stamp(now),)).fetchone()[0] < 4096)
        conn.execute("INSERT INTO approval_review_receipts "
            "(id,approval_request_id,reviewer_id,review_digest,expires_at,used_at,created_at) VALUES(?,?,?,?,?,NULL,?)",
            (receipt, identifier, reviewer, review_hash, _stamp(expiry), _stamp(now)))
        _audit(db, conn, "reviewed", row, actor, review_receipt_id=receipt, review_digest=review_hash)
        return {"approval": _public(conn, row, reviewer, now, db), "document": document,
            "review_receipt_id": receipt, "review_digest": review_hash,
            "review_expires_at": _stamp(expiry), "assurance": "host-trusted"}


def decide(identifier, actor, value):
    _need(type(value) is dict and set(value) == {"decision", "review_receipt_id", "review_digest", "note"}
        and value["decision"] in {"approve", "deny"})
    _text(value["review_receipt_id"], 128)
    _need(type(value["review_digest"]) is str and _SHA.fullmatch(value["review_digest"]))
    note = value["note"]
    _need(note is None or type(note) is str and len(note.encode("utf-8")) <= 500
        and not any(ord(c) < 32 or ord(c) == 127 for c in note))
    with _transaction(write=True) as (conn, db, reviewer, now):
        _need(actor == reviewer)
        row = _find(conn, identifier, reviewer)
        _need(row["status"] == "pending" and now < _epoch(row["expires_at"]))
        wire = _wire(row, db)
        _current(conn, wire, now)
        receipt = conn.execute("SELECT * FROM approval_review_receipts WHERE id=?",
            (value["review_receipt_id"],)).fetchone()
        _need(receipt is not None and receipt["approval_request_id"] == identifier
            and receipt["reviewer_id"] == reviewer and receipt["used_at"] is None
            and now < _epoch(receipt["expires_at"])
            and receipt["review_digest"] == value["review_digest"] == _review_digest(row, _document(wire)))
        stamp, expiry = _stamp(now), _stamp(min(_epoch(row["expires_at"]), now + 60_000))
        authn = {"schema": "serverware.hostTrustedApprovalDecision/v1", "assurance": "host-trusted",
            "reviewerId": reviewer, "reviewReceiptId": receipt["id"], "reviewDigest": receipt["review_digest"]}
        state = "approved" if value["decision"] == "approve" else "denied"
        _need(conn.execute("UPDATE approval_requests SET status=?,approved_until=?,decision_note=?,approved_by=?,approval_authn=? "
            "WHERE id=? AND status='pending'", (state, expiry if state == "approved" else None, note, actor,
                canonical(authn), identifier)).rowcount == 1)
        _need(conn.execute("UPDATE approval_review_receipts SET used_at=? WHERE id=? AND used_at IS NULL",
            (stamp, receipt["id"])).rowcount == 1)
        if state == "approved":
            columns = ("id", "approval_request_id", "state", "principal_id", "route_id", "credential_id",
                "credential_version", "policy_hash", "request_digest", "operation_digest", "approver_policy_json",
                "approver_policy_digest", "uses_remaining", "valid_from", "expires_at", "created_at", "updated_at")
            values = ("host-approval:" + identifier, identifier, "active", *[row[name] for name in columns[3:12]],
                1, stamp, expiry, stamp, stamp)
            conn.execute("INSERT INTO approval_grants (" + ",".join(columns) + ") VALUES(" + ",".join("?" for _ in columns) + ")", values)
        _audit(db, conn, state, row, actor, review_receipt_id=receipt["id"], review_digest=receipt["review_digest"], note=note)
        return _public(conn, _find(conn, identifier, reviewer), reviewer, now, db)


def _response(wire, row, state, expiry):
    return {"apiVersion": RESPONSE_VERSION, "status": state, "approvalId": row["id"],
        "requestDigest": wire["requestDigest"], "operationDigest": wire["operationDigest"],
        "attemptId": wire["attemptId"], "policyHash": wire["policyHash"], "expiresAtEpochMs": expiry}


def _claim(conn, db, reviewer, now, wire):
    _current(conn, wire, now)
    prior = conn.execute("SELECT * FROM approval_grant_consumptions WHERE attempt_id=?", (wire["attemptId"],)).fetchone()
    if prior is not None:
        row = _find(conn, prior["approval_request_id"], reviewer)
        _need(all(prior[name] == wire[field] for name, field in (("principal_id", "principalId"),
            ("route_id", "routeId"), ("credential_id", "credentialId"), ("credential_version", "credentialVersion"),
            ("policy_hash", "policyHash"), ("request_digest", "requestDigest"), ("operation_digest", "operationDigest"))))
        return _response(wire, row, "consumed", _epoch(row["approved_until"]))
    key = "host-approval:" + digest({"request": wire["requestDigest"], "reviewer": reviewer})
    found = conn.execute("SELECT * FROM approval_requests WHERE pending_key=?", (key,)).fetchone()
    row = _owned(found, reviewer) if found is not None else None
    if row is not None:
        retained = _wire(row, db)
        _need(retained["canonicalRequest"] == wire["canonicalRequest"])
        expiry = _epoch(row["approved_until"] if row["status"] == "approved" else row["expires_at"])
        if now >= expiry:
            conn.execute("UPDATE approval_requests SET status='expired',pending_key=NULL WHERE id=?", (row["id"],))
            conn.execute("UPDATE approval_grants SET state='revoked',updated_at=? WHERE approval_request_id=? AND state='active'",
                (_stamp(now), row["id"]))
            _audit(db, conn, "expired", row, reviewer)
            row = None
    if row is None:
        _need(conn.execute("SELECT COUNT(*) FROM approval_requests WHERE status='pending' AND expires_at>?",
            (_stamp(now),)).fetchone()[0] < 1024)
        request, policy = wire["canonicalRequest"]["request"], _policy(reviewer)
        identifier, stamp, expiry = str(uuid.uuid4()), _stamp(now), _stamp(now + 300_000)
        # Only the FK placeholder is created, never an enabled legacy route.
        db._ensure_policy_route_reference(conn, wire["routeId"])
        columns = ("id", "route_id", "method", "url", "status", "requested_at", "expires_at", "principal_id",
            "credential_id", "credential_version", "policy_hash", "request_digest", "operation_digest",
            "canonical_request", "redacted_display", "grant_ttl_seconds", "grant_max_uses", "pending_key",
            "approver_policy_json", "approver_policy_digest")
        document = _document(wire)
        values = (identifier, wire["routeId"], request["method"], db._approval_url_commitment(document["url"]), "pending", stamp, expiry,
            wire["principalId"], wire["credentialId"], wire["credentialVersion"], wire["policyHash"],
            wire["requestDigest"], wire["operationDigest"], db._encrypt_approval_json(canonical(wire["canonicalRequest"])),
            db._encrypt_approval_json(canonical(document)), 60, 1, key, canonical(policy), digest(policy))
        conn.execute("INSERT INTO approval_requests (" + ",".join(columns) + ") VALUES(" + ",".join("?" for _ in columns) + ")", values)
        row = _find(conn, identifier, reviewer)
        _audit(db, conn, "requested", row, wire["principalId"], method=row["method"],
            requested_at=row["requested_at"], expires_at=row["expires_at"], reviewer_id=reviewer,
            approver_policy_digest=row["approver_policy_digest"], url_commitment=row["url"])
    if row["status"] in {"pending", "denied"}:
        return _response(wire, row, row["status"], _epoch(row["expires_at"]))
    _need(row["status"] == "approved" and row["approved_by"] == reviewer)
    grant = conn.execute("SELECT * FROM approval_grants WHERE id=?", ("host-approval:" + row["id"],)).fetchone()
    _need(grant is not None and grant["state"] == "active" and grant["uses_remaining"] == 1
        and _epoch(grant["valid_from"]) <= now < _epoch(grant["expires_at"])
        and all(grant[name] == row[name] for name in ("principal_id", "route_id", "credential_id", "credential_version",
            "policy_hash", "request_digest", "operation_digest", "approver_policy_json", "approver_policy_digest")))
    stamp = _stamp(now)
    _need(conn.execute("UPDATE approval_grants SET state='consumed',uses_remaining=0,consumed_at=?,consumed_by_flow_id=?,updated_at=? "
        "WHERE id=? AND state='active' AND uses_remaining=1", (stamp, wire["attemptId"], stamp, grant["id"])).rowcount == 1)
    _need(conn.execute("UPDATE approval_requests SET status='consumed',pending_key=NULL WHERE id=? AND status='approved'",
        (row["id"],)).rowcount == 1)
    columns = ("id", "grant_id", "approval_request_id", "attempt_id", "flow_id", "principal_id", "route_id",
        "credential_id", "credential_version", "policy_hash", "request_digest", "operation_digest", "approver_policy_digest",
        "outcome", "uses_remaining_before", "uses_remaining_after", "created_at")
    values = (str(uuid.uuid4()), grant["id"], row["id"], wire["attemptId"], wire["attemptId"],
        *[row[name] for name in columns[5:13]], "consumed", 1, 0, stamp)
    conn.execute("INSERT INTO approval_grant_consumptions (" + ",".join(columns) + ") VALUES(" + ",".join("?" for _ in columns) + ")", values)
    _audit(db, conn, "claimed", row, wire["principalId"], attempt_id=wire["attemptId"])
    return _response(wire, row, "claimed", _epoch(grant["expires_at"]))


def claim(value):
    wire = validate_claim(value)
    with _transaction(write=True) as (conn, db, reviewer, now):
        return _claim(conn, db, reviewer, now, wire)
