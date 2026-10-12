"""Ordinary X account journal; borrowed publication/SQLite transactions only.

No provider transport, implicit retry, key bootstrap, generic OAuth cleanup or
native admission lives here. Actual core envelope custody encrypts PKCE and
each bounded response independently. A response is retained before it is judged.
Public status is recovery, never permission to repeat a contact or a mutation.
"""
from __future__ import annotations

import base64
from contextlib import closing
import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import time
import uuid
from urllib.parse import parse_qs

from serverware import db, operator_catalog_schema as catalog
from serverware import operator_x_admission as admission
from serverware import operator_x_oauth_profile as profiles

PREFIX = "operator_x_account_"
INTENTS, WORK, CAPTURES = (PREFIX + name for name in ("intents", "work", "captures"))
MARKER = "operator_x_account"
MAX_INTENTS, MAX_WORK, MAX_ACTIVE = 1024, 2048, 32
MAX_CLEANUP_BYTES = 768 * 1024
# Every admitted consent can create at most one account and that account can
# be fenced only once. Keep this many intent/work slots exclusively available
# to disconnect; refresh never spends the local safety reserve.
DISCONNECT_RESERVE = MAX_INTENTS // 2
REASONS = frozenset({None, "consent_denied", "expired", "exchange_failed", "refresh_failed",
    "persistence_failed", "identity_conflict", "cleanup_unconfirmed"})
_SQL = {
    INTENTS: f"CREATE TABLE {INTENTS} (id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, state_digest TEXT UNIQUE, status TEXT NOT NULL, metadata_json TEXT NOT NULL, envelope_json TEXT NOT NULL)",
    WORK: f"CREATE TABLE {WORK} (id TEXT PRIMARY KEY, operation_id TEXT NOT NULL, credential_id TEXT, status TEXT NOT NULL, metadata_json TEXT NOT NULL, envelope_json TEXT NOT NULL)",
    CAPTURES: f"CREATE TABLE {CAPTURES} (id TEXT PRIMARY KEY, work_id TEXT NOT NULL REFERENCES {WORK}(id), phase TEXT NOT NULL, status TEXT NOT NULL, metadata_json TEXT NOT NULL, envelope_json TEXT NOT NULL, UNIQUE(work_id,phase))",
}


class StoreError(ValueError):
    def __init__(self):
        super().__init__("operator X account operation unavailable")


class StoreNotFound(LookupError):
    def __init__(self):
        super().__init__("operator X account operation not found")


def _need(value):
    if not value:
        raise StoreError()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _hash(value):
    return "sha256:" + hashlib.sha256(_json(value).encode("ascii")).hexdigest()


def _uuid(value):
    _need(type(value) is str and len(value) == 36 and str(uuid.UUID(value)) == value)
    return value


def _opaque(value):
    _need(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{43,128}", value))
    return "sha256:" + hashlib.sha256(value.encode("ascii")).hexdigest()


def _now():
    return int(time.time() * 1000)


def _transaction(conn, *, writing=True):
    from serverware.operator_publication import assert_held
    directory = admission.require_runtime()
    admission.check_connection(conn, directory)
    _need(catalog.active(conn))
    if writing:
        assert_held()
        _need(conn.execute("PRAGMA query_only").fetchone()[0] == 0)
    return directory


def _schema(conn, *, initialize=False):
    rows = conn.execute("SELECT name,type,tbl_name,sql FROM main.sqlite_master WHERE lower(name) GLOB ? OR lower(tbl_name) GLOB ? LIMIT 17",
        (PREFIX + "*", PREFIX + "*")).fetchall()
    if not rows:
        if not initialize:
            raise StoreNotFound()
        # Initialization belongs to first consent, never discovery/refresh.
        credentials = conn.execute("SELECT metadata FROM credentials LIMIT 4097").fetchall()
        _need(len(credentials) <= 4096 and not any(MARKER in json.loads(row[0]) for row in credentials))
        for sql in _SQL.values():
            conn.execute(sql)
        return _schema(conn)
    expected = set(_SQL) | {"sqlite_autoindex_" + name + "_1" for name in _SQL} | {
        "sqlite_autoindex_" + INTENTS + "_2", "sqlite_autoindex_" + CAPTURES + "_2"}
    _need(len(rows) == len(expected) and {row["name"] for row in rows} == expected)
    for row in rows:
        if row["name"] in _SQL:
            _need(row["type"] == "table" and row["tbl_name"] == row["name"]
                and " ".join(row["sql"].split()) == " ".join(_SQL[row["name"]].split()))
        else:
            _need(row["type"] == "index" and row["sql"] is None)


def _selection(conn, expected=None):
    from serverware.operator_x_configuration import retained_public_binding
    value = retained_public_binding(conn)
    _need(value is not None and (expected is None or value == expected))
    return value


def _review(conn, revision, policy_hash):
    catalog.require_revision(conn, revision)
    found = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
    if found is None or found[0] != policy_hash:
        raise catalog.CatalogConflict()
    catalog.validate_bindings(conn)


def _seal(identifier, value):
    raw = _json(value)
    db.validate_credential_secret(raw)
    return _json(db._envelope_values(identifier, raw, 1))


def _open(row):
    envelope = json.loads(row["envelope_json"])
    _need(type(envelope) is dict and envelope.get("credential_version") == 1)
    value = json.loads(db.decrypt_secret_envelope({"id": row["id"], **envelope}))
    _need(type(value) is dict)
    return value


def _get(conn, table, identifier):
    _uuid(identifier)
    row = conn.execute("SELECT * FROM " + table + " WHERE id=?", (identifier,)).fetchone()
    if row is None:
        raise StoreNotFound()
    _need(type(row["metadata_json"]) is str and len(row["metadata_json"].encode()) <= 32768)
    value = json.loads(row["metadata_json"])
    _need(type(value) is dict and value["id"] == row["id"] and value["status"] == row["status"]
        and row["metadata_json"] == _json(value))
    return dict(row), value


def _save(conn, table, value, old_status):
    _need(conn.execute("UPDATE " + table + " SET status=?,metadata_json=? WHERE id=? AND status=?",
        (value["status"], _json(value), value["id"], old_status)).rowcount == 1)


def _public(intent):
    return {"schema": "serverware.operatorXAccountOperation/v1", "operation_id": intent["id"],
        "kind": intent["kind"], "status": intent["status"], "credential_id": intent["credential_id"],
        "reason": intent["reason"], "created_at": intent["created_at"],
        "expires_at_epoch_ms": intent["expires_at_epoch_ms"]}


def _audit(conn, event, intent, **fields):
    db.append_audit_event(conn, event_type="operator_catalog.x_oauth." + event,
        actor_type="admin", actor_id=intent["actor_id"], event={"operation_id": intent["id"],
        "provider": "x", "credential_id": intent["credential_id"], **fields})


def begin(conn, selection, *, operation_id, actor_id, name, review, state, browser_nonce, verifier, expires_at_epoch_ms):
    _transaction(conn); _selection(conn, selection); _schema(conn, initialize=True)
    _uuid(operation_id)
    _need(type(actor_id) is str and 1 <= len(actor_id) <= 512 and type(name) is str and 1 <= len(name) <= 128)
    _need(set(review) == {"expected_revision", "expected_policy_hash"})
    _review(conn, review["expected_revision"], review["expected_policy_hash"])
    _need(type(expires_at_epoch_ms) is int and _now() < expires_at_epoch_ms <= _now() + 600_000)
    state_digest, nonce_digest = _opaque(state), _opaque(browser_nonce)
    _opaque(verifier)
    counts = conn.execute("SELECT count(*),sum(status IN ('consent_pending','exchanging','uncertain','disconnect_pending')) FROM " + INTENTS).fetchone()
    _need(counts[0] < MAX_INTENTS - DISCONNECT_RESERVE and (counts[1] or 0) < MAX_ACTIVE)
    if conn.execute("SELECT 1 FROM " + INTENTS + " WHERE id=? OR state_digest=?", (operation_id, state_digest)).fetchone():
        raise catalog.CatalogConflict()
    value = {"id": operation_id, "operation_id": operation_id, "actor_id": actor_id, "name": name,
        "kind": "consent", "status": "consent_pending", "selection": selection,
        "state_digest": state_digest, "nonce_digest": nonce_digest, "created_at": db.iso_now(),
        "expires_at_epoch_ms": expires_at_epoch_ms, "credential_id": None, "reason": None,
        "revision": review["expected_revision"] + 1, "policy_hash": review["expected_policy_hash"]}
    conn.execute("INSERT INTO " + INTENTS + " VALUES(?,?,?,?,?,?)", (operation_id, actor_id, state_digest,
        value["status"], _json(value), _seal(operation_id, {"verifier": verifier})))
    catalog.advance_revision(conn, review["expected_revision"])
    _audit(conn, "consent_started", value, revision=value["revision"])
    return value


def _new_work(conn, intent, *, operation, credential=None, secret=None):
    limit = MAX_WORK if operation == "disconnect" else MAX_WORK - DISCONNECT_RESERVE
    _need(conn.execute("SELECT count(*) FROM " + WORK).fetchone()[0] < limit)
    if credential is not None and operation != "disconnect":
        _need(conn.execute("SELECT 1 FROM " + WORK + " WHERE credential_id=? AND status NOT IN ('adopted','disconnected','rejected') LIMIT 1",
            (credential["id"],)).fetchone() is None)
    identifier = str(uuid.uuid4())
    value = {"id": identifier, "operation_id": intent["id"], "actor_id": intent["actor_id"],
        "operation": operation, "status": "exchange_in_flight", "selection": intent["selection"],
        "credential_id": credential["id"] if credential else None,
        "generation": credential["credential_version"] if credential else None,
        "metadata": credential["metadata"] if credential else None, "name": intent["name"],
        "revision": intent["revision"], "policy_hash": intent["policy_hash"],
        "created_at": db.iso_now(), "pid": os.getpid(), "deadline": None,
        "started_wall_ms": _now(), "started_monotonic": time.monotonic(), "reason": None}
    conn.execute("INSERT INTO " + WORK + " VALUES(?,?,?,?,?,?)", (identifier, intent["id"], value["credential_id"],
        value["status"], _json(value), _seal(identifier, {"secret": secret})))
    return value


def consume_callback(conn, *, state, browser_nonce, error=False):
    _transaction(conn); _schema(conn)
    state_digest, nonce_digest = _opaque(state), _opaque(browser_nonce)
    found = conn.execute("SELECT id FROM " + INTENTS + " WHERE state_digest=?", (state_digest,)).fetchone()
    if found is None:
        raise StoreError()
    row, intent = _get(conn, INTENTS, found[0])
    _need(intent["kind"] == "consent" and intent["status"] == "consent_pending"
        and hmac.compare_digest(intent["nonce_digest"], nonce_digest) and _now() < intent["expires_at_epoch_ms"])
    _selection(conn, intent["selection"]); _review(conn, intent["revision"], intent["policy_hash"])
    _need(type(error) is bool)
    intent["status"] = "denied" if error else "exchanging"
    intent["reason"] = "consent_denied" if error else None
    intent["revision"] = catalog.advance_revision(conn, intent["revision"])
    _save(conn, INTENTS, intent, "consent_pending")
    work = None if error else _new_work(conn, intent, operation="code")
    _audit(conn, "consent_denied" if error else "exchange_claimed", intent, revision=intent["revision"])
    return {"intent": intent, "work_id": work["id"] if work else None,
        "selection": intent["selection"], "code_verifier": _open(row)["verifier"] if work else None}


def status(conn, operation_id, actor_id):
    _transaction(conn, writing=False); _schema(conn)
    _, intent = _get(conn, INTENTS, operation_id)
    if intent["actor_id"] != actor_id:
        raise StoreNotFound()
    _selection(conn, intent["selection"])
    return _public(intent)


def _current(conn, credential_id, expected_version=None, *, disconnect_review=False):
    from serverware import operator_catalog_x_oauth as accounts
    _transaction(conn, writing=False); _schema(conn)
    row = conn.execute("SELECT * FROM credentials WHERE id=?", (_uuid(credential_id),)).fetchone()
    _need(row is not None)
    core = db.row_to_credential(row)
    metadata = accounts.validate_account_metadata(core["metadata"])
    selection = _selection(conn)
    record = next((item for item in catalog.read_catalog(conn)["credentials"] if item["id"] == credential_id), None)
    _need(record is not None)
    accounts.validate_record(record, dict(row), profiles.parse_profile(selection["public_profile"]))
    accounts.validate_configuration_binding(record, selection)
    _, intent = _get(conn, INTENTS, metadata[MARKER]["intent_id"])
    held_refresh = (disconnect_review and intent["status"] == "uncertain" and intent["reason"] == "refresh_failed")
    _need((intent["status"] == "connected" or held_refresh) and intent["credential_id"] == credential_id)
    floor = conn.execute("SELECT last_version FROM credential_generations WHERE credential_id=?", (credential_id,)).fetchone()
    _need(floor is not None and type(core["credential_version"]) is int and floor[0] == core["credential_version"]
        and 1 <= core["credential_version"] < 9_007_199_254_740_991)
    if expected_version is not None:
        _need(type(expected_version) is int and expected_version >= 1 and core["credential_version"] >= expected_version)
    return {"credential": core, "metadata": metadata, "selection": selection}


def current(conn, credential_id, expected_version=None):
    return _current(conn, credential_id, expected_version)


def _lease_binding(conn, binding, actual):
    from serverware import operator_catalog_x_oauth as accounts
    _need(type(binding) is dict and set(binding) == {"principal_id", "route_id", "credential_id", "policy_hash"}
        and binding["credential_id"] == actual["credential"]["id"]
        and conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()[0] == binding["policy_hash"])
    accounts.require_lease_binding(conn, principal_id=binding["principal_id"], route_id=binding["route_id"],
        credential_id=binding["credential_id"], core_credential=actual["credential"],
        profile=profiles.parse_profile(actual["selection"]["public_profile"]))


def _refresh_capacity(tokens, unresolved):
    from serverware import operator_x_oauth_protocol as protocol
    # Reserve both unknown new token fields and their maximum encoded response
    # size before issuance. Rotation/reuse is deliberately not assumed.
    _need(unresolved is False and len(tokens) <= 62
        and len(_json(tokens).encode("ascii")) <= MAX_CLEANUP_BYTES - protocol.MAX_TOKEN_RESPONSE_BYTES - 4096)


def claim_refresh(conn, *, credential_id, expected_version, lease_binding):
    _transaction(conn)
    actual = current(conn, credential_id, expected_version)
    core = actual["credential"]
    if core["credential_version"] != expected_version:
        raise catalog.CatalogConflict()
    _lease_binding(conn, lease_binding, actual)
    tokens, unresolved = _cleanup_material(conn, [credential_id])
    _refresh_capacity(tokens, unresolved)
    _, intent = _get(conn, INTENTS, actual["metadata"][MARKER]["intent_id"])
    resources = catalog.read_catalog(conn)
    intent = {**intent, "revision": resources["revision"], "policy_hash": conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()[0]}
    secret = db.decrypt_secret_envelope(conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone())
    work = _new_work(conn, intent, operation="refresh", credential=core, secret=secret)
    work["lease_binding"] = dict(lease_binding)
    _save(conn, WORK, work, "exchange_in_flight")
    return {"work_id": work["id"], "selection": actual["selection"], "credential_id": credential_id,
        "generation": expected_version, "metadata": actual["metadata"], "secret": secret,
        "lease_binding": dict(work["lease_binding"])}


def _request_hash(request):
    return _hash({"profile": profiles.public_record(request.profile), "phase": request.phase,
        "method": request.method, "url": request.url, "headers": list(request.headers),
        "body": base64.b64encode(request.body).decode("ascii")})


def _phase(request):
    if request.phase != "revoke":
        return request.phase
    values = parse_qs(request.body.decode("ascii"), strict_parsing=True)
    _need(values.get("token_type_hint") in (["access_token"], ["refresh_token"]))
    _need(set(values) == {"token", "token_type_hint"} and len(values["token"]) == 1)
    return "revoke:" + values["token_type_hint"][0] + ":" + hashlib.sha256(values["token"][0].encode("ascii")).hexdigest()


def _live(work):
    now, monotonic = _now(), time.monotonic()
    _need(work["pid"] == os.getpid() and now >= work["started_wall_ms"]
        and monotonic >= work["started_monotonic"] and work["deadline"] is not None
        and monotonic < work["deadline"])


def claim_contact(conn, work_id, *, request, deadline):
    from serverware import operator_x_oauth_protocol as protocol
    from serverware.http_client import HttpDeadline
    _transaction(conn); _schema(conn)
    row, work = _get(conn, WORK, work_id)
    _selection(conn, work["selection"])
    protocol._request(request, {"code", "refresh", "identity", "revoke"})
    _need(profiles.public_record(request.profile) == work["selection"]["public_profile"]
        and type(deadline) is HttpDeadline and math.isfinite(deadline.expires_at))
    if work["deadline"] is None:
        _need(deadline.expires_at <= time.monotonic() + 60)
        work["deadline"] = deadline.expires_at
    _need(work["deadline"] == deadline.expires_at)
    _live(work)
    phase = _phase(request)
    _need(work["status"] in {"exchange_in_flight", "material_held", "cleanup_pending"})
    if phase in {"code", "refresh"}:
        _need(work["operation"] == phase and work["status"] == "exchange_in_flight")
        form = parse_qs(request.body.decode("ascii"), strict_parsing=True)
        if phase == "code":
            intent_row, intent = _get(conn, INTENTS, work["operation_id"])
            _need(intent["status"] == "exchanging" and _now() < intent["expires_at_epoch_ms"]
                and form["code_verifier"] == [_open(intent_row)["verifier"]])
        else:
            actual = current(conn, work["credential_id"], work["generation"])
            _need(actual["credential"]["credential_version"] == work["generation"]
                and actual["metadata"] == work["metadata"])
            _lease_binding(conn, work["lease_binding"], actual)
            _need(form["refresh_token"] == [json.loads(_open(row)["secret"])["refresh_token"]])
    elif phase == "identity":
        _need(work["operation"] in {"code", "refresh"} and work["status"] == "material_held")
        if work["operation"] == "refresh":
            actual = current(conn, work["credential_id"], work["generation"])
            _need(actual["credential"]["credential_version"] == work["generation"]
                and actual["metadata"] == work["metadata"])
            _lease_binding(conn, work["lease_binding"], actual)
        else:
            _, intent = _get(conn, INTENTS, work["operation_id"])
            _need(intent["status"] == "exchanging" and _now() < intent["expires_at_epoch_ms"])
        captured = _captured(conn, work_id, work["operation"])
        raw = protocol._unique(protocol._decoded(base64.b64decode(captured["body"])))
        _need(type(raw) is dict and request.headers == (("Authorization", "Bearer " + raw["access_token"]), ("Accept", "application/json")))
    else:
        _need(work["operation"] == "disconnect" and work["status"] == "cleanup_pending")
        _fence_current(conn, work)
        tokens = _open(row)["cleanup_tokens"]
        values = parse_qs(request.body.decode("ascii"), strict_parsing=True)
        _need({"token": values["token"][0], "token_type_hint": values["token_type_hint"][0]} in tokens)
    identifier = str(uuid.uuid4())
    contact = {"id": identifier, "status": "claimed", "work_id": work_id, "phase": phase,
        "request_sha256": _request_hash(request), "profile_binding_digest": request.profile.binding_digest,
        "deadline": deadline.expires_at, "created_wall_ms": _now(), "created_monotonic": time.monotonic()}
    try:
        conn.execute("INSERT INTO " + CAPTURES + " VALUES(?,?,?,?,?,?)", (identifier, work_id, phase,
            "claimed", _json(contact), _seal(identifier, {})))
    except sqlite3.IntegrityError:
        raise StoreError() from None
    _save(conn, WORK, work, row["status"])


def capture(conn, work_id, captured):
    """Retain late bytes before classification or freshness/selection denial."""
    from serverware import operator_x_transport as transport
    _transaction(conn); _schema(conn)
    _, work = _get(conn, WORK, work_id)
    transport.require_capture(captured, request=captured.request, work_id=work_id, deadline=captured.deadline)
    phase = _phase(captured.request)
    found = conn.execute("SELECT id FROM " + CAPTURES + " WHERE work_id=? AND phase=?", (work_id, phase)).fetchone()
    _need(found is not None)
    row, contact = _get(conn, CAPTURES, found[0])
    _need(contact["status"] == "claimed")
    matched = (contact["request_sha256"] == _request_hash(captured.request)
        and contact["profile_binding_digest"] == captured.profile_binding_digest
        and contact["deadline"] == captured.deadline.expires_at)
    value = {"status": captured.status, "headers": list(captured.headers),
        "body": base64.b64encode(captured.body).decode("ascii"),
        "wire_prefix": base64.b64encode(captured.wire_prefix).decode("ascii"),
        "complete": captured.complete, "outcome": captured.outcome, "matched": matched,
        "received_wall_ms": _now(), "received_monotonic": time.monotonic()}
    envelope = _seal(row["id"], value)
    contact["status"] = "captured"
    _need(conn.execute("UPDATE " + CAPTURES + " SET status='captured',metadata_json=?,envelope_json=? WHERE id=? AND status='claimed'",
        (_json(contact), envelope, row["id"])).rowcount == 1)
    if work["status"] == "exchange_in_flight" and phase == work["operation"]:
        work["status"] = "material_held"
        _save(conn, WORK, work, "exchange_in_flight")
    # No raised post-retention check here: caller must commit the capture first.


def _captured(conn, work_id, phase, request=None):
    found = conn.execute("SELECT id FROM " + CAPTURES + " WHERE work_id=? AND phase=?", (work_id, phase)).fetchone()
    _need(found is not None)
    row, contact = _get(conn, CAPTURES, found[0])
    _need(contact["status"] == "captured" and (request is None or contact["request_sha256"] == _request_hash(request)))
    value = _open(row)
    _need(value["complete"] is True and value["matched"] is True)
    return value


def hold(conn, work_id, *, reason):
    _transaction(conn); _schema(conn)
    _need(reason in REASONS and reason is not None)
    row, work = _get(conn, WORK, work_id)
    _, intent = _get(conn, INTENTS, work["operation_id"])
    if work["status"] in {"adopted", "disconnected"}:
        return _public(intent)  # A later failure cannot pretend rollback.
    work.update(status="uncertain", reason=reason)
    _save(conn, WORK, work, row["status"])
    previous = intent["status"]
    intent.update(status="uncertain", reason=reason)
    _save(conn, INTENTS, intent, previous)
    _audit(conn, "operation_uncertain", intent, work_id=work_id, reason=reason)
    return _public(intent)


def _response(value):
    return {"status": value["status"], "headers": tuple(tuple(pair) for pair in value["headers"]),
        "body": base64.b64decode(value["body"], validate=True)}


def _expiry_from_contact(created_wall_ms, lifetime):
    _need(type(created_wall_ms) is int and type(lifetime) is int and lifetime > 0)
    expiry = created_wall_ms + lifetime * 1000
    _need(_now() < expiry <= 9_007_199_254_740_991)
    return expiry


def adoption_inputs(conn, work_id, *, token, identity):
    """Reclassify actual retained observations, not caller success flags."""
    from serverware import operator_x_oauth_protocol as protocol
    _transaction(conn); _schema(conn)
    _, work = _get(conn, WORK, work_id)
    _, intent = _get(conn, INTENTS, work["operation_id"])
    _selection(conn, work["selection"]); _live(work)
    _need(work["status"] == "material_held" and work["operation"] in {"code", "refresh"}
        and type(token) is protocol.AcceptedToken and type(identity) is protocol.AcceptedIdentity
        and token.request.phase == work["operation"]
        and profiles.public_record(token.request.profile) == work["selection"]["public_profile"]
        and identity.request == protocol.identity_request(token.request.profile, token.access_token))
    captured = _captured(conn, work_id, work["operation"], token.request)
    identity_capture = _captured(conn, work_id, "identity", identity.request)
    _need(protocol.classify_token_response(token.request, **_response(captured)) == token
        and protocol.classify_identity_response(identity.request, **_response(identity_capture)) == identity
        and work["started_wall_ms"] <= captured["received_wall_ms"] <= identity_capture["received_wall_ms"] <= _now()
        and work["started_monotonic"] <= captured["received_monotonic"] <= identity_capture["received_monotonic"] <= time.monotonic())
    profile, selection = token.request.profile, work["selection"]
    contact_id = conn.execute("SELECT id FROM " + CAPTURES + " WHERE work_id=? AND phase=?",
        (work_id, work["operation"])).fetchone()[0]
    _, contact = _get(conn, CAPTURES, contact_id)
    _need(work["started_wall_ms"] <= contact["created_wall_ms"] <= captured["received_wall_ms"])
    expiry = _expiry_from_contact(contact["created_wall_ms"], token.expires_in)
    if work["operation"] == "code":
        _need(intent["status"] == "exchanging" and intent["credential_id"] is None
            and _now() < intent["expires_at_epoch_ms"])
        _review(conn, work["revision"], work["policy_hash"])
        rows = conn.execute("SELECT metadata FROM credentials LIMIT 4097").fetchall()
        _need(len(rows) <= 4096)
        for row in rows:
            other = json.loads(row[0])
            _need(not (other.get("provider_id") == "x" and other.get("provider_subject") == identity.subject
                and other.get("oauth_client_id", other.get("x_app_id")) == profile.client_id))
        binding = {"schema": "serverware.operatorXAccountBinding/v1", "owner_id": selection["owner_id"],
            "configuration_operation_id": selection["operation_id"], "config_version": selection["config_version"],
            "profile_binding_digest": selection["profile_binding_digest"], "intent_id": intent["id"]}
    else:
        actual = current(conn, work["credential_id"], work["generation"])
        _need(actual["credential"]["credential_version"] == work["generation"]
            and actual["metadata"] == work["metadata"]
            and identity.subject == work["metadata"]["provider_subject"])
        _lease_binding(conn, work["lease_binding"], actual)
        binding = work["metadata"][MARKER]
    metadata = {"oauth": True, "provider": "x.oauth2", "provider_id": "x",
        "oauth_client_id": profile.client_id, "x_app_id": profile.client_id,
        "provider_subject": identity.subject, "provider_account": "@" + identity.username,
        "provider_identity_verified": True, "scopes": list(profiles.SCOPES), "refreshable": True,
        "injection_field": "access_token", "expires_at_epoch_ms": expiry, MARKER: binding}
    secret = {"access_token": token.access_token, "refresh_token": token.refresh_token,
        "token_type": "Bearer", "scope": " ".join(profiles.SCOPES), "expires_at_epoch_ms": expiry}
    if token.refresh_token_expires_in is not None:
        expires = _expiry_from_contact(contact["created_wall_ms"], token.refresh_token_expires_in)
        secret["refresh_token_expires_at_epoch_ms"] = metadata["refresh_token_expires_at_epoch_ms"] = expires
    from serverware.operator_catalog_x_oauth import validate_account_metadata
    validate_account_metadata(metadata, profile)
    return work, intent, _json(secret), metadata


def _adopt(conn, work_id, *, token, identity, operation):
    from serverware import operator_catalog_x_oauth as accounts
    work, intent, _, _ = adoption_inputs(conn, work_id, token=token, identity=identity)
    _need(work["operation"] == operation)
    core = db.adopt_operator_x_account(conn, work_id=work_id, token=token, identity=identity)
    resources = catalog.read_catalog(conn)
    record = accounts.record_fields(core, token.request.profile)
    if operation == "refresh":
        prior = next(item for item in resources["credentials"] if item["id"] == core["id"])
        record = {**prior, **record}
    catalog.save_resource(conn, "credentials", record, create=operation == "code")
    previous = intent["status"]
    intent.update(status="connected", credential_id=core["id"], reason=None)
    intent["revision"] = catalog.advance_revision(conn, resources["revision"])
    _save(conn, INTENTS, intent, previous)
    work.update(status="adopted", credential_id=core["id"], adopted_generation=core["credential_version"])
    _need(conn.execute("UPDATE " + WORK + " SET credential_id=?,status=?,metadata_json=? WHERE id=? AND status='material_held'",
        (core["id"], work["status"], _json(work), work_id)).rowcount == 1)
    catalog.validate_bindings(conn)
    _audit(conn, "account_connected" if operation == "code" else "account_refreshed", intent,
        work_id=work_id, previous_credential_generation=work["generation"],
        credential_generation=core["credential_version"], revision=intent["revision"])
    _live(work)
    return core


def adopt(conn, work_id, *, token, identity):
    return _adopt(conn, work_id, token=token, identity=identity, operation="code")


def adopt_refresh(conn, work_id, *, token, identity):
    return _adopt(conn, work_id, token=token, identity=identity, operation="refresh")


def _family(conn, credential_id):
    actual = _current(conn, credential_id, disconnect_review=True)
    resources = catalog.read_catalog(conn)
    catalog.validate_bindings(conn, resources)
    profile = profiles.parse_profile(actual["selection"]["public_profile"])
    from serverware import operator_catalog_x_oauth as accounts
    rows = conn.execute("SELECT * FROM credentials LIMIT 4097").fetchall()
    _need(len(rows) <= 4096)
    selected = []
    for row in rows:
        metadata = json.loads(row["metadata"])
        if (metadata.get("provider_id") != "x" or metadata.get("provider_subject") != actual["metadata"]["provider_subject"]
                or metadata.get("oauth_client_id", metadata.get("x_app_id")) != profile.client_id):
            continue
        record = next((item for item in resources["credentials"] if item["id"] == row["id"]), None)
        _need(record is not None)
        accounts.validate_record(record, dict(row), profile)
        accounts.validate_configuration_binding(record, actual["selection"])
        selected.append((dict(row), record))
    _need(1 <= len(selected) <= 16)
    identifiers = sorted(row["id"] for row, _ in selected)
    rules = sorted(rule["id"] for rule in resources["access_rules"]
        if rule["status"] == "active" and rule["credential_id"] in identifiers)
    return actual, resources, selected, identifiers, rules


def review_disconnect(conn, credential_id, actor_id):
    _transaction(conn, writing=False)
    _need(type(actor_id) is str and 1 <= len(actor_id) <= 512)
    actual, resources, _, identifiers, rules = _family(conn, credential_id)
    value = {"schema": "serverware.operatorXDisconnectReview/v1", "credential_id": credential_id,
        "expected_credential_generation": actual["credential"]["credential_version"],
        "expected_revision": resources["revision"], "expected_policy_hash": conn.execute(
            "SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()[0],
        "affected_credential_ids": identifiers, "affected_rule_ids": rules}
    return {**value, "review_digest": _hash({**value, "actor_id": actor_id,
        "selection": actual["selection"], "metadata": actual["metadata"]})}


def _cleanup_material(conn, identifiers):
    """All known material remains encrypted; unknown issuance is never success."""
    from serverware import operator_x_oauth_protocol as protocol
    tokens, unresolved = set(), False
    def collect(raw):
        nonlocal unresolved
        parsed = protocol._decoded(raw)
        if type(parsed) is not protocol._Pairs:
            unresolved = True
            return
        for key, value in parsed:
            if key in {"access_token", "refresh_token"}:
                try:
                    protocol._opaque(value)
                except (ValueError, TypeError):
                    unresolved = True
                    continue
                candidate = tokens | {(key, value)}
                encoded = [{"token_type_hint": hint, "token": token} for hint, token in sorted(candidate)]
                if len(candidate) > 64 or len(_json(encoded).encode("ascii")) > MAX_CLEANUP_BYTES:
                    # Never let excess/uncertain issuance prevent the local
                    # fence. All originals remain in their encrypted records;
                    # a bounded subset cannot establish cleanup completion.
                    unresolved = True
                else:
                    tokens.add((key, value))
    for identifier in identifiers:
        row = conn.execute("SELECT * FROM credentials WHERE id=?", (identifier,)).fetchone()
        collect(db.decrypt_secret_envelope(row).encode())
    rows = conn.execute("SELECT * FROM " + WORK + " LIMIT ?", (MAX_WORK + 1,)).fetchall()
    _need(len(rows) <= MAX_WORK)
    for row in rows:
        _, work = _get(conn, WORK, row["id"])
        if work["operation"] not in {"code", "refresh"}:
            continue
        # Unknown initial identity can belong to this same configured account.
        if work["credential_id"] not in identifiers:
            if work["credential_id"] is None and work["status"] not in {"adopted", "rejected"}:
                unresolved = True
            continue
        secret = _open(row).get("secret")
        if secret is not None:
            collect(secret.encode())
        contacts = conn.execute("SELECT * FROM " + CAPTURES + " WHERE work_id=? AND phase=?",
            (work["id"], work["operation"])).fetchall()
        _need(len(contacts) <= 1)
        if not contacts or contacts[0]["status"] != "captured":
            unresolved = True
            continue
        material = _open(contacts[0])
        collect(base64.b64decode(material["body"], validate=True))
        if work["status"] != "adopted" or not material["complete"] or not material["matched"]:
            unresolved = True
    _need(1 <= len(tokens) <= 64)
    return [{"token_type_hint": hint, "token": token} for hint, token in sorted(tokens)], unresolved


def fence_disconnect(conn, selection, *, payload, actor_id):
    from serverware import operator_catalog_policy as policy
    _transaction(conn); _schema(conn); _selection(conn, selection)
    value = payload.model_dump() if hasattr(payload, "model_dump") else dict(payload)
    _need(set(value) == {"operation_id", "credential_id", "expected_revision", "expected_policy_hash",
        "expected_credential_generation", "review_digest"})
    _uuid(value["operation_id"])
    if conn.execute("SELECT 1 FROM " + INTENTS + " WHERE id=?", (value["operation_id"],)).fetchone():
        raise catalog.CatalogConflict()
    reviewed = review_disconnect(conn, value["credential_id"], actor_id)
    if any(value[field] != reviewed[field] for field in value if field != "operation_id"):
        raise catalog.CatalogConflict()
    actual, resources, selected, identifiers, rules = _family(conn, value["credential_id"])
    tokens, unresolved = _cleanup_material(conn, identifiers)
    _need(conn.execute("SELECT count(*) FROM " + INTENTS).fetchone()[0] < MAX_INTENTS)
    now = db.iso_now()
    intent = {"id": value["operation_id"], "operation_id": value["operation_id"], "actor_id": actor_id,
        "name": actual["credential"]["name"], "kind": "disconnect", "status": "disconnect_pending",
        "selection": selection, "state_digest": None, "nonce_digest": None, "created_at": now,
        "expires_at_epoch_ms": None, "credential_id": value["credential_id"], "reason": None,
        "revision": resources["revision"], "policy_hash": value["expected_policy_hash"]}
    conn.execute("INSERT INTO " + INTENTS + " VALUES(?,?,?,?,?,?)", (intent["id"], actor_id, None,
        intent["status"], _json(intent), _seal(intent["id"], {})))
    work = _new_work(conn, intent, operation="disconnect", credential=actual["credential"])
    for core, record in selected:
        _need(conn.execute("UPDATE credentials SET lifecycle_status='revocation_pending',updated_at=? "
            "WHERE id=? AND credential_version=? AND lifecycle_status='active'",
            (now, core["id"], core["credential_version"])).rowcount == 1)
        catalog.save_resource(conn, "credentials", {**record, "status": "quarantined", "quarantined_at": now,
            "quarantine_reason": "operator_x_cleanup_fence", "quarantine_work_id": work["id"]})
    for rule in resources["access_rules"]:
        if rule["id"] in rules:
            catalog.save_resource(conn, "access_rules", {**rule, "status": "revoked", "revoked_at": now})
    published = policy.publish(conn)
    revision = catalog.advance_revision(conn, resources["revision"])
    intent.update(revision=revision, policy_hash=published["policy_hash"])
    _save(conn, INTENTS, intent, "disconnect_pending")
    work.update(status="cleanup_pending", revision=revision, policy_hash=published["policy_hash"],
        affected_credential_ids=identifiers, affected_rule_ids=rules, unresolved_issuance=unresolved,
        generations={core["id"]: core["credential_version"] for core, _ in selected})
    _need(conn.execute("UPDATE " + WORK + " SET status=?,metadata_json=?,envelope_json=? WHERE id=? AND status='exchange_in_flight'",
        (work["status"], _json(work), _seal(work["id"], {"cleanup_tokens": tokens}), work["id"])).rowcount == 1)
    _audit(conn, "disconnect_fenced", intent, work_id=work["id"], revision=revision,
        policy_hash=work["policy_hash"], credential_ids=identifiers, revoked_rule_ids=rules)
    return {"work_id": work["id"], "selection": selection, "credential_id": value["credential_id"],
        "generation": actual["credential"]["credential_version"], "metadata": actual["metadata"],
        "cleanup_tokens": tokens, "operation": _public(intent)}


def _fence_current(conn, work):
    _need(work["operation"] == "disconnect" and work["status"] == "cleanup_pending")
    _selection(conn, work["selection"])
    resources = catalog.read_catalog(conn)
    catalog.validate_bindings(conn, resources)
    _need(resources["revision"] == work["revision"] and conn.execute(
        "SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()[0] == work["policy_hash"])
    for identifier in work["affected_credential_ids"]:
        row = conn.execute("SELECT lifecycle_status,credential_version FROM credentials WHERE id=?", (identifier,)).fetchone()
        record = next((item for item in resources["credentials"] if item["id"] == identifier), None)
        _need(row is not None and row[0] == "revocation_pending" and row[1] == work["generations"][identifier]
            and record is not None and record.get("quarantine_work_id") == work["id"]
            and record["status"] == "quarantined")
    _need(not any(rule["status"] == "active" and rule["credential_id"] in work["affected_credential_ids"]
        for rule in resources["access_rules"]))


def materialize_disconnect(work_id):
    """Only export an already committed fence; no startup, send or retry."""
    from serverware import operator_publication, operator_demo_store
    with operator_publication.exclusive():
        with closing(db.connect()) as conn:
            conn.execute("PRAGMA query_only=ON"); conn.execute("BEGIN")
            _transaction(conn, writing=False); _schema(conn)
            _, work = _get(conn, WORK, work_id)
            _fence_current(conn, work)
        operator_demo_store.materialize()


def finish_cleanup(conn, work_id, *, receipts):
    from serverware import operator_x_oauth_protocol as protocol
    _transaction(conn); _schema(conn)
    row, work = _get(conn, WORK, work_id)
    _fence_current(conn, work); _live(work)
    _need(work["unresolved_issuance"] is False)
    tokens = _open(row)["cleanup_tokens"]
    _need(type(receipts) is tuple and len(receipts) == len(tokens))
    observed = set()
    for receipt in receipts:
        _need(type(receipt) is protocol.AcceptedRevocation)
        request = receipt.request
        protocol._request(request, {"revoke"})
        _need(profiles.public_record(request.profile) == work["selection"]["public_profile"])
        phase = _phase(request)
        _need(phase not in observed)
        observed.add(phase)
        form = parse_qs(request.body.decode("ascii"), strict_parsing=True)
        _need({"token_type_hint": form["token_type_hint"][0], "token": form["token"][0]} in tokens)
        material = _captured(conn, work_id, phase, request)
        _need(protocol.classify_revoke_response(request, **_response(material)) == receipt)
    resources = catalog.read_catalog(conn)
    now = db.iso_now()
    for identifier in work["affected_credential_ids"]:
        record = next(item for item in resources["credentials"] if item["id"] == identifier)
        _need(conn.execute("DELETE FROM credentials WHERE id=? AND lifecycle_status='revocation_pending' AND credential_version=?",
            (identifier, work["generations"][identifier])).rowcount == 1)
        catalog.save_resource(conn, "credentials", {**record, "status": "revoked", "revoked_at": now})
    _, intent = _get(conn, INTENTS, work["operation_id"])
    intent.update(status="disconnected", reason=None, revision=catalog.advance_revision(conn, resources["revision"]))
    _save(conn, INTENTS, intent, "disconnect_pending")
    work.update(status="disconnected")
    _save(conn, WORK, work, "cleanup_pending")
    catalog.validate_bindings(conn)
    _audit(conn, "disconnected", intent, work_id=work_id, revision=intent["revision"],
        credential_ids=work["affected_credential_ids"])
    _live(work)
    return _public(intent)
