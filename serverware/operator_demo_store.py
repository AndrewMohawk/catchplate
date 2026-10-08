"""Local signed operator policy and encrypted credentials; no native authority receipts."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import threading
import time
from urllib.parse import urlsplit
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Literal

_LOCK = threading.RLock()
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RETENTION_MS = 24 * 60 * 60 * 1000
MAX_ACTIVE_CONNECTIONS = 32
MAX_RETAINED_CONNECTIONS = 1024
_PUBLIC_FIELDS = ("id", "name", "upstream_url", "methods", "auth_type", "header_name",
    "credential_id", "principal_id", "created_at", "token_expires_at_epoch_ms",
    "request_fields", "response_fields", "query_keys", "allowed_headers")
_REVOCATION_FIELDS = ("connection_id", "name", "credential_id", "principal_id", "revoked_at",
    "expected_policy_hash", "revocation_policy_hash", "sequence")


class ConnectionInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=128)
    upstream_url: str = Field(min_length=1, max_length=2048)
    methods: list[Literal["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]] = Field(min_length=1, max_length=6)
    auth_type: Literal["bearer", "header"]
    header_name: str | None = Field(default=None, max_length=128)
    secret: str = Field(min_length=1, max_length=8192)
    request_fields: list[str] = Field(default_factory=list, max_length=64)
    response_fields: list[str] = Field(min_length=1, max_length=64)
    query_keys: list[str] = Field(default_factory=list, max_length=64)
    allowed_headers: list[str] = Field(default_factory=lambda: ["accept", "user-agent"], max_length=32)


class RevocationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    connection_id: str = Field(min_length=36, max_length=36)
    expected_policy_hash: str = Field(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("connection_id")
    @classmethod
    def canonical_identifier(cls, value: str) -> str:
        if str(uuid.UUID(value)) != value:
            raise ValueError("connection identifier must be a canonical UUID")
        return value


class RevocationNotFound(Exception):
    """No active connection or durable revocation matches this identifier."""


class RevocationConflict(Exception):
    """The submitted review or retained local binding no longer matches."""


class ConnectionLimitReached(Exception):
    def __init__(self, reason: Literal["active", "retained"]):
        self.reason = reason
        super().__init__("operator demo connection admission limit reached")


def _require():
    from serverware import operator_demo, db
    if not operator_demo.active():
        raise RuntimeError("operator demo store unavailable")
    return db


def _public(row: dict) -> dict:
    return {key: row[key] for key in _PUBLIC_FIELDS}


def _build(rows: list[dict], sequence: int, initial_hash: str) -> dict:
    from serverware import operator_demo
    principals, credentials, routes = [], [], []
    for row in rows:
        principals.append({"id": row["principal_id"], "proxyAuthorization": {
            "scheme": "Bearer", "tokenId": row["id"], "tokenSha256": row["token_sha256"],
            "expiresAtEpochMs": row["token_expires_at_epoch_ms"]}})
        bearer = row["auth_type"] == "bearer"
        credentials.append({"id": row["credential_id"], "credentialType": "static",
            "provider": "operator-demo", "providerSubject": row["id"],
            "injection": {"type": "bearer", "header": "Authorization"} if bearer else
                {"type": "header", "name": row["header_name"], "prefix": ""}})
        parsed = urlsplit(row["upstream_url"])
        request = {"allowedHeaders": row["allowed_headers"], "allowedQueryKeys": row["query_keys"],
            "allowedMediaTypes": ["application/json"] if row["request_fields"] else [],
            "bodyMode": "json" if row["request_fields"] else "none",
            "maxBodyBytes": 65536 if row["request_fields"] else 0,
            "operation": {"name": "operator." + row["id"]}}
        if row["request_fields"]:
            request["allowedFields"] = row["request_fields"]
        route = {"id": "operator." + row["id"], "principals": [row["principal_id"]],
            "match": {"scheme": "https", "host": parsed.hostname, "port": parsed.port or 443,
                "methods": row["methods"], "paths": [parsed.path or "/"]},
            "credentialRef": row["credential_id"], "adapter": {"type": "generic.rest", "config": {
                "credentialMode": "required", "credentialBinding": {"credentialType": "static",
                    "provider": "operator-demo", "subjects": [row["id"]],
                    "secretClass": "bearerToken" if bearer else "customHeader"},
                "request": request, "response": {"mode": "json", "maxBodyBytes": 1048576,
                    "allowedFields": row["response_fields"]}}}, "constraints": []}
        if parsed.hostname == "demo-upstream":
            route["match"]["resolvedCidrs"] = operator_demo.settings()["fixture_cidrs"]
        if row["request_fields"]:
            route["constraints"].append({"id": "operator-body-" + row["id"], "type": "jsonBody",
                "contentTypes": ["application/json"], "allowedFields": row["request_fields"]})
        routes.append(route)
    if not principals:
        # The schema requires a route. Its only principal is permanently expired;
        # the unknown token preimage is discarded, so this cannot dispatch.
        principals.append({"id": "agent:operator-demo:empty", "proxyAuthorization": {
            "scheme": "Bearer", "tokenId": "empty", "tokenSha256": initial_hash,
            "expiresAtEpochMs": 1}})
        target = urlsplit(operator_demo.settings()["allowed_upstreams"][0])
        match = {"scheme": "https", "host": target.hostname, "port": target.port or 443,
            "methods": ["GET"], "paths": ["/__serverware_operator_demo_unconfigured__"]}
        if target.hostname == "demo-upstream":
            match["resolvedCidrs"] = operator_demo.settings()["fixture_cidrs"]
        routes.append({"id": "operator.empty", "principals": ["agent:operator-demo:empty"], "match": match,
            "adapter": {"type": "generic.rest", "config": {"credentialMode": "none", "noCredentialProof": {
                "credentialRefAbsent": True, "secretInjectionDisabled": True,
                "sensitiveHeadersForwarded": False, "authorizationForwarded": False},
                "request": {"allowedHeaders": [], "allowedQueryKeys": [], "allowedMediaTypes": [],
                    "bodyMode": "none", "maxBodyBytes": 0, "operation": {"name": "operator.empty"}},
                "response": {"mode": "headersOnly", "maxBodyBytes": 0}}}, "constraints": []})
    for route in routes:
        route["adapter"]["config"]["request"]["valueRules"] = []
        response = route["adapter"]["config"]["response"]
        response["contentTypes"] = [] if response["mode"] == "headersOnly" else ["application/json"]
        response["allowedHeaders"] = []
        response["error"] = {"mode": "json", "maxBodyBytes": 65536,
            "allowedFields": ["error", "code", "message"], "allowedHeaders": [], "onInvalid": "block"}
        route["constraints"].append({"id": route["id"] + ".envelope", "type": "responseEnvelope",
            "phase": "response", "statusCodes": [204] if response["mode"] == "headersOnly" else
                [200, 201, 202, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503, 504],
            "bodyPresence": "forbidden" if response["mode"] == "headersOnly" else "required",
            "contentTypes": response["contentTypes"], "allowedResponseHeaderNames": [], "responseHeaderRules": []})
    return {"apiVersion": "serverware.policy/v1", "kind": "PolicyBundle",
        "metadata": {"id": "serverware-operator-demo", "sequence": sequence, "rollbackEpoch": 1},
        "defaults": {"action": "deny", "failMode": "closed", "unknownHosts": "block",
            "unknownPaths": "block", "validationFailure": "block"},
        "principals": principals, "credentials": credentials, "routes": routes}


def _signed(rows: list[dict], sequence: int, initial_hash: str) -> tuple[str, str]:
    from serverware import policy_bundle
    signed = policy_bundle.sign_policy_bundle(_build(rows, sequence, initial_hash))
    snapshot = policy_bundle.compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
    return policy_bundle.canonical_json(signed), snapshot.hash


def _state(row) -> dict:
    return {"policy_id": "serverware-operator-demo", "sequence": row["sequence"],
        "rollback_epoch": 1, "policy_hash": row["policy_hash"], "updated_at": row["updated_at"]}


def initialize() -> None:
    db = _require()
    from serverware import operator_demo
    with _LOCK, db.connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS operator_demo_settings (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), settings_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS operator_demo_connections (
                id TEXT PRIMARY KEY, metadata_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS operator_demo_revocations (
                connection_id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS operator_demo_policy (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), sequence INTEGER NOT NULL,
                policy_hash TEXT NOT NULL, signed_bundle_json TEXT NOT NULL,
                initial_hash TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS operator_demo_nonces (
                recipient_key_id TEXT NOT NULL, nonce_sha256 TEXT NOT NULL,
                expires_at_epoch_ms INTEGER NOT NULL, PRIMARY KEY(recipient_key_id,nonce_sha256));
        """)
        conn.execute("BEGIN IMMEDIATE")
        settings = operator_demo.settings()
        pinned = json.dumps({key: settings[key] for key in ("allowed_upstreams", "fixture_cidrs")}, sort_keys=True)
        previous = conn.execute("SELECT settings_json FROM operator_demo_settings WHERE singleton=1").fetchone()
        if previous is None:
            conn.execute("INSERT INTO operator_demo_settings VALUES(1,?)", (pinned,))
        elif previous[0] != pinned:
            raise RuntimeError("operator demo deployment allowlist changed; separate data required")
        if conn.execute("SELECT 1 FROM operator_demo_policy").fetchone() is None:
            initial_hash = "sha256:" + hashlib.sha256(secrets.token_bytes(32)).hexdigest()
            raw, digest = _signed([], 1, initial_hash)
            conn.execute("INSERT INTO operator_demo_policy VALUES(1,1,?,?,?,?)",
                (digest, raw, initial_hash, db.iso_now()))
        conn.commit()
        materialize()


def materialize() -> None:
    """DB is authoritative after commit; durable atomic replace is recoverable on startup."""
    db = _require()
    from serverware.config import POLICY_BUNDLE_PATH
    with _LOCK, db.connect() as conn:
        row = conn.execute("SELECT signed_bundle_json FROM operator_demo_policy WHERE singleton=1").fetchone()
        if row is None:
            raise RuntimeError("operator demo committed policy unavailable")
        raw = row[0].encode("utf-8")
        path = Path(POLICY_BUNDLE_PATH)
        if path.is_symlink():
            raise RuntimeError("operator demo policy file cannot be a symlink")
        if path.exists() and path.read_bytes() == raw:
            return
        fd, temporary = tempfile.mkstemp(prefix=".operator-policy-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def get_policy_high_water() -> dict | None:
    db = _require()
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone()
    return _state(row) if row else None


def get_policy_publication(policy_hash: str) -> dict | None:
    state = get_policy_high_water()
    if not state or state["policy_hash"] != policy_hash:
        return None
    return {**state, "scope": "active", "status": "committed", "previous_policy_hash": None,
        "created_at": state["updated_at"], "committed_at": state["updated_at"]}


def verify_policy_high_water(**values) -> dict:
    state = get_policy_high_water()
    if (values.pop("_connection", None) is not None or values.pop("_allow_pending", False)
            or state is None or any(state.get(k) != v for k, v in values.items())):
        raise ValueError("signed policy does not match committed operator demo state")
    return state


def create_connection(payload: ConnectionInput, actor_id: str) -> tuple[dict, str, str]:
    db = _require()
    from serverware import operator_demo, policy_bundle
    upstream, _ = operator_demo.origin(payload.upstream_url, target=True)
    if upstream not in operator_demo.settings()["allowed_upstreams"]:
        raise ValueError("destination is not deployment-allowlisted")
    if (payload.name != payload.name.strip() or any(ord(c) < 32 for c in payload.name)
            or any(ord(c) < 32 or ord(c) > 126 for c in payload.secret)
            or len(set(payload.methods)) != len(payload.methods)):
        raise ValueError("invalid connection input")
    for fields in (payload.request_fields, payload.response_fields):
        if any(len(item) > 256 or policy_bundle.RESPONSE_FIELD_PATH_RE.fullmatch(item) is None for item in fields):
            raise ValueError("invalid field projection")
    for values in (payload.request_fields, payload.response_fields, payload.query_keys, payload.allowed_headers):
        if len(set(values)) != len(values) or any(not item or len(item) > 256 or any(ord(c) < 33 or ord(c) > 126 for c in item) for item in values):
            raise ValueError("invalid input allowlist")
    if payload.auth_type == "bearer" and payload.header_name not in {None, "Authorization"}:
        raise ValueError("bearer injection uses Authorization")
    identifier, token = str(uuid.uuid4()), secrets.token_urlsafe(32)
    record = payload.model_dump(exclude={"secret"})
    record.update(id=identifier, principal_id="agent:operator-demo:" + identifier,
        header_name="Authorization" if payload.auth_type == "bearer" else payload.header_name,
        token_sha256="sha256:" + hashlib.sha256(token.encode("ascii")).hexdigest(),
        token_expires_at_epoch_ms=time.time_ns() // 1_000_000 + _RETENTION_MS,
        created_at=db.iso_now())
    with _LOCK, db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = [json.loads(row[0]) for row in conn.execute("SELECT metadata_json FROM operator_demo_connections ORDER BY rowid")]
        if len(rows) >= MAX_ACTIVE_CONNECTIONS:
            raise ConnectionLimitReached("active")
        retained_count = conn.execute("SELECT COUNT(*) FROM operator_demo_revocations").fetchone()[0]
        if len(rows) + retained_count >= MAX_RETAINED_CONNECTIONS:
            raise ConnectionLimitReached("retained")
        if conn.execute("SELECT 1 FROM operator_demo_revocations WHERE connection_id=?", (identifier,)).fetchone():
            raise RuntimeError("operator demo connection identifier was previously revoked")
        state = conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone()
        if state is None:
            raise RuntimeError("operator demo policy unavailable")
        credential = db.create_credential(payload.name, "bearer" if payload.auth_type == "bearer" else "header",
            payload.secret, {"provider_id": "operator-demo", "provider_subject": identifier,
                "secret_class": "bearerToken" if payload.auth_type == "bearer" else "customHeader"}, _connection=conn)
        record["credential_id"] = credential["id"]
        raw, digest = _signed([*rows, record], state["sequence"] + 1, state["initial_hash"])
        conn.execute("INSERT INTO operator_demo_connections VALUES (?,?)", (identifier, json.dumps(record, sort_keys=True)))
        conn.execute("UPDATE operator_demo_policy SET sequence=?,policy_hash=?,signed_bundle_json=?,updated_at=? WHERE singleton=1",
            (state["sequence"] + 1, digest, raw, db.iso_now()))
        db.append_audit_event(conn, event_type="operator_demo.connection.created", actor_type="admin", actor_id=actor_id,
            event={"connection_id": identifier, "credential_id": credential["id"], "principal_id": record["principal_id"],
                "policy_hash": digest, "upstream_origin": upstream, "methods": payload.methods})
        conn.commit()
        # Failure leaves a durable pending publication, never a claim of activation.
        try:
            materialize()
        except Exception:
            pass
    return _public(record), token, digest


def _revocation_receipt(row) -> dict:
    receipt = json.loads(row["receipt_json"])
    return {key: receipt[key] for key in _REVOCATION_FIELDS}


def revoke_connection(payload: RevocationInput, actor_id: str) -> dict:
    """Commit one exact local revocation; replay returns its original receipt.

    This removes local proxy access and the stored provider credential. It does
    not revoke that credential with its provider or undo an upstream request.
    """
    db = _require()
    with _LOCK, db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        previous = conn.execute("SELECT * FROM operator_demo_revocations WHERE connection_id=?",
            (payload.connection_id,)).fetchone()
        target = conn.execute("SELECT metadata_json FROM operator_demo_connections WHERE id=?",
            (payload.connection_id,)).fetchone()
        if previous is not None:
            receipt = _revocation_receipt(previous)
            if receipt["expected_policy_hash"] != payload.expected_policy_hash or target is not None:
                raise RevocationConflict()
            # A lost HTTP response is not permission for a second mutation.
            return receipt
        if target is None:
            raise RevocationNotFound()
        state = conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone()
        if state is None:
            raise RuntimeError("operator demo policy unavailable")
        if state["policy_hash"] != payload.expected_policy_hash:
            raise RevocationConflict()
        record = json.loads(target["metadata_json"])
        credential = conn.execute("SELECT id, name, kind, metadata, lifecycle_status FROM credentials WHERE id=?",
            (record.get("credential_id"),)).fetchone()
        metadata = json.loads(credential["metadata"]) if credential is not None else None
        bearer = record.get("auth_type") == "bearer"
        if (record.get("id") != payload.connection_id
                or record.get("principal_id") != "agent:operator-demo:" + payload.connection_id
                or record.get("auth_type") not in {"bearer", "header"}
                or credential is None or not isinstance(metadata, dict)
                or credential["name"] != record.get("name")
                or credential["kind"] != ("bearer" if bearer else "header")
                or credential["lifecycle_status"] != "active"
                or metadata.get("provider_id") != "operator-demo"
                or metadata.get("provider_subject") != payload.connection_id
                or metadata.get("secret_class") != ("bearerToken" if bearer else "customHeader")
                or metadata.get("oauth") is True):
            raise RevocationConflict()
        remaining = [json.loads(row[0]) for row in conn.execute(
            "SELECT metadata_json FROM operator_demo_connections WHERE id<>? ORDER BY rowid", (payload.connection_id,))]
        if any(row.get("credential_id") == record["credential_id"]
                or row.get("principal_id") == record["principal_id"] for row in remaining):
            raise RevocationConflict()
        sequence = state["sequence"] + 1
        raw, digest = _signed(remaining, sequence, state["initial_hash"])
        receipt = {"connection_id": payload.connection_id, "name": record["name"],
            "credential_id": record["credential_id"], "principal_id": record["principal_id"],
            "revoked_at": db.iso_now(), "expected_policy_hash": payload.expected_policy_hash,
            "revocation_policy_hash": digest, "sequence": sequence}
        if not db.delete_credential(record["credential_id"], _connection=conn):
            raise RevocationConflict()
        if conn.execute("DELETE FROM operator_demo_connections WHERE id=?", (payload.connection_id,)).rowcount != 1:
            raise RevocationConflict()
        conn.execute("UPDATE operator_demo_policy SET sequence=?,policy_hash=?,signed_bundle_json=?,updated_at=? WHERE singleton=1",
            (sequence, digest, raw, receipt["revoked_at"]))
        conn.execute("INSERT INTO operator_demo_revocations VALUES (?,?)",
            (payload.connection_id, json.dumps(receipt, sort_keys=True)))
        db.append_audit_event(conn, event_type="operator_demo.connection.revoked", actor_type="admin", actor_id=actor_id,
            event=receipt)
        conn.commit()
        # The DB commit is authoritative, even if publication needs recovery.
        # A pending observation must never be reported as enforced revocation.
        try:
            materialize()
        except Exception:
            pass
    return receipt


def loaded_policy_hash() -> str | None:
    _require()
    from serverware.config import DECISION_GATE_BASE
    if not DECISION_GATE_BASE:
        return None
    client = None
    try:
        parsed = urlsplit(DECISION_GATE_BASE)
        if (parsed.scheme != "http" or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or parsed.hostname not in {"decision-gate-rs", "127.0.0.1", "localhost"}):
            return None
        client = http.client.HTTPConnection(parsed.hostname, parsed.port or 9091, timeout=1)
        client.request("GET", "/healthz", headers={"Connection": "close"})
        response = client.getresponse()
        body = response.read(131073)
        if response.status != 200 or len(body) > 131072:
            return None
        value = json.loads(body)
        if not isinstance(value, dict):
            return None
        digest = value.get("policy_hash")
        if value.get("ok") is True and isinstance(digest, str) and _SHA.fullmatch(digest):
            return digest
    except (OSError, ValueError, http.client.HTTPException):
        return None
    finally:
        if client is not None:
            client.close()
    return None


def _revocation_observation(receipt: dict, committed: str | None, loaded: str | None,
        active_ids: set[str]) -> dict:
    return {**receipt, "policy_hash": committed,
        "enforcement": "enforced" if committed is not None and loaded == committed
            and receipt["connection_id"] not in active_ids else "pending"}


def revoke_result(connection_id: str) -> dict:
    """Read the durable receipt and current policy together, then observe reload."""
    db = _require()
    with db.connect() as conn:
        conn.execute("BEGIN")
        row = conn.execute("SELECT * FROM operator_demo_revocations WHERE connection_id=?", (connection_id,)).fetchone()
        if row is None:
            raise RevocationNotFound()
        receipt = _revocation_receipt(row)
        state = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
        active = conn.execute("SELECT 1 FROM operator_demo_connections WHERE id=?", (connection_id,)).fetchone()
    committed = state["policy_hash"] if state else None
    loaded = loaded_policy_hash()
    return {"revocation": _revocation_observation(receipt, committed, loaded, {connection_id} if active else set()),
        "policy_hash": committed, "loaded_policy_hash": loaded}


def status() -> dict:
    db = _require()
    from serverware import operator_demo
    with db.connect() as conn:
        conn.execute("BEGIN")
        rows = [json.loads(row[0]) for row in conn.execute("SELECT metadata_json FROM operator_demo_connections ORDER BY rowid")]
        revocations = [_revocation_receipt(row) for row in conn.execute("SELECT * FROM operator_demo_revocations ORDER BY rowid")]
        state = conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone()
    committed = state["policy_hash"] if state else None
    loaded = loaded_policy_hash()
    activation = "active" if loaded is not None and loaded == committed else "pending"
    now_epoch_ms = time.time_ns() // 1_000_000
    settings = operator_demo.settings()
    active_ids = {row["id"] for row in rows}
    return {"schema": operator_demo.SCHEMA, "mode": "operator-development", "syntheticOnly": False,
        "productionReady": False, "hardwareVerified": False, "proxy_url": settings["proxy_url"],
        "allowed_upstreams": settings["allowed_upstreams"], "active_policy_hash": committed,
        "connection_limits": {"active_max": MAX_ACTIVE_CONNECTIONS, "retained_max": MAX_RETAINED_CONNECTIONS,
            "active_count": len(rows), "retained_count": len(rows) + len(revocations)},
        "revocations": [_revocation_observation(receipt, committed, loaded, active_ids)
            for receipt in revocations],
        "loaded_policy_hash": loaded, "connections": [{**_public(row), "policy_hash": committed,
            "activation": activation,
            "client_status": "expired" if now_epoch_ms >= row["token_expires_at_epoch_ms"] else
                "ready" if activation == "active" else "pending"} for row in rows]}


def _nonce_values(key, nonce, now):
    _require()
    if (not isinstance(key, str) or not _SHA.fullmatch(key) or not isinstance(nonce, str)
            or not _SHA.fullmatch(nonce) or type(now) is not int or not 0 <= now < (1 << 63) - _RETENTION_MS):
        raise ValueError("invalid operator demo nonce")


def reserve_credential_lease_nonce(key, nonce, *, now_epoch_ms):
    _nonce_values(key, nonce, now_epoch_ms)
    db = _require()
    from serverware.config import CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES
    with db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM operator_demo_nonces WHERE expires_at_epoch_ms<=?", (now_epoch_ms,))
        if conn.execute("SELECT 1 FROM operator_demo_nonces WHERE recipient_key_id=? AND nonce_sha256=?", (key, nonce)).fetchone():
            return "replay"
        if conn.execute("SELECT COUNT(*) FROM operator_demo_nonces").fetchone()[0] >= min(CREDENTIAL_LEASE_REPLAY_MAX_ENTRIES, 100000):
            return "capacity"
        conn.execute("INSERT INTO operator_demo_nonces VALUES (?,?,?)", (key, nonce, now_epoch_ms + _RETENTION_MS))
    return None


def credential_lease_nonce_reserved(key, nonce, *, now_epoch_ms):
    _nonce_values(key, nonce, now_epoch_ms)
    db = _require()
    with db.connect() as conn:
        return conn.execute("SELECT 1 FROM operator_demo_nonces WHERE recipient_key_id=? AND nonce_sha256=? AND expires_at_epoch_ms>?",
            (key, nonce, now_epoch_ms)).fetchone() is not None
