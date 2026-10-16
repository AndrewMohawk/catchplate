"""Durable ordinary, host-trusted ownership of one reviewed ECR image publication.

This is not TEE authority. SQLite and the operator publication lock fence the
single application owner. Only acknowledged reducer checkpoints are persisted;
request bytes and sealed image handles stay process-local. A signing lease is
one-shot: its possible-send record commits before signed bytes leave the control
plane. Lost or invalid write acknowledgements never reopen a publication.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid

from serverware import ecr_image_custody as custody
from serverware import ecr_publication_plan as planner
from serverware import ecr_sdk_protocol as protocol

SCHEMA = "serverware.ecrPublication/v1"
MAX_PUBLICATIONS = 1024
MAX_ACTIVE_PUBLICATIONS = 4
MAX_LIFETIME_SECONDS = 1800
MAX_ATTEMPTS = 4096
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PROCESS = str(uuid.uuid4())
_PID = os.getpid()
_TERMINAL = {"published", "denied", "expired", "failed", "uncertain"}
_PENDING = {"preparing", "reserved", "possible_send"}
_HANDLES: dict[str, _Held] = {}


class PublicationConflict(ValueError):
    def __init__(self):
        super().__init__("ECR publication changed or is unavailable")


class PublicationNotFound(ValueError):
    def __init__(self):
        super().__init__("ECR publication not found")


class PublicationExpired(PublicationConflict):
    """The transaction contains only a terminal expiry and its audit."""


def _need(value):
    if not value:
        raise PublicationConflict()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _digest(value):
    return "sha256:" + hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def _identifier(value):
    try:
        _need(type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).version == 4)
    except (ValueError, AttributeError):
        raise PublicationConflict() from None
    return value


def _clock():
    return planner.Clock(time.time_ns() // 1_000_000_000, time.monotonic_ns())


def _boot():
    value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    _identifier(value)
    return value


def _profile():
    from serverware import config, db, operator_demo
    _need(operator_demo.active() and not db.metadata_uses_postgres()
        and config.GRANT_STORE_BACKEND == "sqlite" and not config.ATOMIC_RELEASE_AUTHORIZATION_ENABLED)
    return db, config


def readiness():
    """Read-only local readiness; callers must also join the live gate descriptor."""
    try:
        _need(os.getpid() == _PID)
        db, _ = _profile()
        from serverware import operator_ecr_artifacts
        if not operator_ecr_artifacts.configuration_ready():
            return False
        with db.metadata_connection() as conn:
            value = conn.execute("SELECT schema_version,owner_process,boot_id FROM operator_ecr_owner WHERE singleton=1").fetchone()
            return (value is not None and value["schema_version"] == 1
                and value["owner_process"] == _PROCESS and value["boot_id"] == _boot())
    except Exception:
        return False


ready = readiness


def _audit(db, conn, event, row, actor=None, **extra):
    binding = json.loads(row["binding_json"])
    db.append_audit_event(conn, event_type="operator.ecr_publication." + event,
        actor_type="admin" if event in {"reviewed", "approved", "denied"} else "proxy",
        actor_id=actor or binding["principal_id"], event={"assurance": "host-trusted",
            "publication_id": row["id"], "principal_id": binding["principal_id"],
            "route_id": binding["route_id"], "credential_id": binding["credential_id"],
            "credential_generation": binding["credential_generation"], "policy_hash": binding["policy_hash"],
            "manifest_digest": row["manifest_digest"], "artifact_sha256": row["artifact_sha256"], **extra})


def initialize(conn):
    """Additive startup migration and process fencing, in the caller's EX transaction."""
    global _PROCESS, _PID
    from serverware import operator_publication
    db, _ = _profile()
    operator_publication.assert_held()
    _need(type(conn) is sqlite3.Connection and conn.in_transaction)
    if os.getpid() != _PID:
        # A fork inherits Python objects, not durable ownership. Fence the old
        # owner explicitly, discard inherited custody and recover normally.
        for identifier in list(_HANDLES):
            _drop(identifier)
        _PROCESS, _PID = str(uuid.uuid4()), os.getpid()
    conn.execute("""CREATE TABLE IF NOT EXISTS operator_ecr_owner (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL CHECK(schema_version=1),
        owner_process TEXT NOT NULL, boot_id TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS operator_ecr_publications (
        id TEXT PRIMARY KEY, status TEXT NOT NULL CHECK(status IN
            ('staging','awaiting_review','approved','active','suspended','published','denied','expired','failed','uncertain')),
        binding_json TEXT NOT NULL, manifest_digest TEXT NOT NULL, artifact_sha256 TEXT NOT NULL,
        artifact_json TEXT, checkpoint_json TEXT, boot_id TEXT NOT NULL, owner_process TEXT,
        created_at_epoch_ms INTEGER NOT NULL, expires_at_epoch_ms INTEGER NOT NULL,
        deadline_monotonic_ns INTEGER NOT NULL, revision INTEGER NOT NULL DEFAULT 0,
        attempts INTEGER NOT NULL DEFAULT 0, review_receipt_id TEXT, review_digest TEXT,
        review_expires_at_epoch_ms INTEGER, reviewer_id TEXT, decision_note TEXT,
        child_id TEXT UNIQUE, child_action TEXT, child_status TEXT, child_request_sha256 TEXT, child_binding_sha256 TEXT,
        child_response_sha256 TEXT, terminal_reason TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS operator_ecr_child_ids (
        id TEXT PRIMARY KEY, publication_id TEXT NOT NULL, request_binding_sha256 TEXT NOT NULL)""")
    previous = conn.execute("SELECT * FROM operator_ecr_owner WHERE singleton=1").fetchone()
    boot, clock = _boot(), _clock()
    if previous is not None and previous["owner_process"] == _PROCESS:
        _need(previous["boot_id"] == boot)
        return
    rows = conn.execute("SELECT * FROM operator_ecr_publications WHERE status NOT IN "
        "('published','denied','expired','failed','uncertain') LIMIT ?", (MAX_PUBLICATIONS + 1,)).fetchall()
    _need(len(rows) <= MAX_PUBLICATIONS)
    for original in rows:
        row = dict(original)
        if row["child_status"] in _PENDING:
            # A reserved write after a crash is conservative even if signing had
            # not completed. Never infer that a provider could not have seen it.
            state = "failed" if row["child_action"] == "BatchCheckLayerAvailability" else "uncertain"
        elif (row["boot_id"] != boot or clock.unix_seconds * 1000 >= row["expires_at_epoch_ms"]
                or clock.monotonic_ns >= row["deadline_monotonic_ns"]):
            state = "expired"
        elif row["status"] == "active":
            state = "suspended"
        else:
            continue
        conn.execute("UPDATE operator_ecr_publications SET status=?,owner_process=NULL,terminal_reason=?,"
            "revision=revision+1 WHERE id=?", (state, "owner_restarted", row["id"]))
        _audit(db, conn, "recovered", row, resulting_status=state)
    conn.execute("INSERT INTO operator_ecr_owner VALUES(1,1,?,?) ON CONFLICT(singleton) DO UPDATE SET "
        "owner_process=excluded.owner_process,boot_id=excluded.boot_id", (_PROCESS, boot))


@contextmanager
def _transaction():
    _need(os.getpid() == _PID)
    db, config = _profile()
    from serverware import operator_publication
    with operator_publication.exclusive(), db.metadata_connection() as conn:
        _need(type(conn) is sqlite3.Connection)
        conn.execute("PRAGMA busy_timeout=1000")
        conn.execute("BEGIN IMMEDIATE")
        owner = conn.execute("SELECT * FROM operator_ecr_owner WHERE singleton=1").fetchone()
        _need(owner is not None and owner["owner_process"] == _PROCESS and owner["boot_id"] == _boot())
        try:
            yield conn, db, config.ADMIN_USER_ID, _clock()
            conn.commit()
        except PublicationExpired:
            conn.commit()
            raise


def _find(conn, identifier):
    _identifier(identifier)
    value = conn.execute("SELECT * FROM operator_ecr_publications WHERE id=?", (identifier,)).fetchone()
    if value is None:
        raise PublicationNotFound()
    return dict(value)


def _binding(conn, application_id, access_rule_id, policy_hash, now):
    from serverware import db, operator_catalog_schema as catalog, policy_bundle
    current = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
    snapshot = policy_bundle.get_policy_snapshot()
    _need(current is not None and snapshot is not None and current["policy_hash"] == policy_hash == snapshot.hash)
    records = catalog.read_catalog(conn)
    applications = [item for item in records["applications"] if item["id"] == application_id]
    rules = [item for item in records["access_rules"] if item["id"] == access_rule_id]
    _need(len(applications) == len(rules) == 1)
    application, rule = applications[0], rules[0]
    _need(application["status"] == rule["status"] == "active" and rule["application_id"] == application_id
        and rule.get("operation_bundle") == "aws_ecr_publish_v1" and rule.get("approval_mode") == "host_review_v1"
        and application["token_expires_at_epoch_ms"] > now.unix_seconds * 1000)
    credential = db._operator_aws_current(conn, rule["credential_id"])
    _need(credential is not None)
    core, metadata = credential
    expiry = metadata.get("expires_at")
    expiry_ms = None
    if expiry is not None:
        from serverware.aws_ecr_signing import _expiry_seconds
        expiry_ms = _expiry_seconds(expiry) * 1000
        _need(expiry_ms > now.unix_seconds * 1000)
    routes = [item for item in snapshot.routes if item.id == rule["route_id"]]
    _need(len(routes) == 1 and routes[0].credential_ref == core["id"]
        and application["principal_id"] in routes[0].principals)
    scope = {key: rule[key] for key in ("registry_id", "region", "repository_name", "image_tag")}
    protocol.Scope(scope["registry_id"], scope["region"], scope["repository_name"])
    return {"application_id": application_id, "access_rule_id": access_rule_id,
        "principal_id": application["principal_id"], "route_id": rule["route_id"],
        "credential_id": core["id"], "credential_generation": core["credential_version"],
        "credential_expires_at_epoch_ms": expiry_ms,
        "policy_hash": policy_hash, "token_version": application.get("token_version", 1),
        "token_sha256": application["token_sha256"],
        "token_expires_at_epoch_ms": application["token_expires_at_epoch_ms"],
        "rule_sha256": _digest(rule), "scope": scope}


def _current(conn, row, now):
    previous = json.loads(row["binding_json"])
    current = _binding(conn, previous["application_id"], previous["access_rule_id"], previous["policy_hash"], now)
    _need(current == previous)
    return current


def _drop(identifier):
    held = _HANDLES.pop(identifier, None)
    if held is not None:
        held.image.close()


def _terminal(conn, db, row, state, reason):
    _need(state in _TERMINAL)
    conn.execute("UPDATE operator_ecr_publications SET status=?,terminal_reason=?,revision=revision+1 "
        "WHERE id=?", (state, reason, row["id"]))
    _audit(db, conn, state, row, reason=reason, child_id=row["child_id"], action=row["child_action"],
        request_sha256=row["child_request_sha256"])
    _drop(row["id"])


def _live(conn, db, row, clock):
    _need(row["status"] not in _TERMINAL)
    if (row["boot_id"] != _boot() or clock.unix_seconds * 1000 >= row["expires_at_epoch_ms"]
            or clock.monotonic_ns >= row["deadline_monotonic_ns"]):
        state = "uncertain" if row["child_status"] == "possible_send" and row["child_action"] != "BatchCheckLayerAvailability" else "expired"
        _terminal(conn, db, row, state, "deadline_elapsed")
        raise PublicationExpired()


def _public(row, now=None):
    binding = json.loads(row["binding_json"])
    checkpoint = json.loads(row["checkpoint_json"]) if row["checkpoint_json"] else None
    result = {key: row[key] for key in ("id", "status", "manifest_digest", "artifact_sha256",
        "created_at_epoch_ms", "expires_at_epoch_ms", "revision", "reviewer_id", "decision_note")}
    result.update({key: binding[key] for key in ("application_id", "access_rule_id", "principal_id", "route_id",
        "credential_id", "credential_generation", "policy_hash", "scope")})
    result.update(schema=SCHEMA, assurance="host-trusted", artifact=json.loads(row["artifact_json"]) if row["artifact_json"] else None,
        child={"id": row["child_id"], "action": row["child_action"], "status": row["child_status"],
            "request_sha256": row["child_request_sha256"], "request_binding_sha256": row["child_binding_sha256"],
            "response_sha256": row["child_response_sha256"]} if row["child_id"] else None,
        progress={key: checkpoint[key] for key in ("calls", "ready_digests", "upload", "part_bytes")}
            if checkpoint else None, terminal_reason=row["terminal_reason"])
    # Never expose token verifiers, private staging paths or AWS tuple fields.
    if now and row["status"] not in _TERMINAL and now.unix_seconds * 1000 >= row["expires_at_epoch_ms"]:
        result["status"] = "uncertain" if row["child_status"] == "possible_send" and row["child_action"] != "BatchCheckLayerAvailability" else "expired"
    return result


def create(application_id, access_rule_id, expected_policy_hash, manifest_digest, artifact_sha256,
        *, principal_id=None, ttl_seconds=MAX_LIFETIME_SECONDS):
    for item in (application_id, access_rule_id):
        _identifier(item)
    _need(all(type(item) is str and _SHA.fullmatch(item) for item in
        (expected_policy_hash, manifest_digest, artifact_sha256)))
    _need(type(ttl_seconds) is int and 1 <= ttl_seconds <= MAX_LIFETIME_SECONDS)
    with _transaction() as (conn, db, reviewer, now):
        binding = _binding(conn, application_id, access_rule_id, expected_policy_hash, now)
        _need(principal_id is None or principal_id == binding["principal_id"])
        # A wall-expired parent must release its process-owned memfds before a
        # replacement can occupy an active slot; ignoring expired rows in a
        # COUNT alone would permit retained memory to grow across generations.
        expired = conn.execute("SELECT * FROM operator_ecr_publications WHERE status NOT IN "
            "('published','denied','expired','failed','uncertain') AND "
            "(expires_at_epoch_ms<=? OR deadline_monotonic_ns<=? OR boot_id<>?) LIMIT ?",
            (now.unix_seconds * 1000, now.monotonic_ns, _boot(), MAX_PUBLICATIONS + 1)).fetchall()
        _need(len(expired) <= MAX_PUBLICATIONS)
        for original in expired:
            previous = dict(original)
            state = "uncertain" if previous["child_status"] == "possible_send" and previous["child_action"] != "BatchCheckLayerAvailability" else "expired"
            _terminal(conn, db, previous, state, "deadline_elapsed")
        _need(conn.execute("SELECT COUNT(*) FROM operator_ecr_publications").fetchone()[0] < MAX_PUBLICATIONS)
        _need(conn.execute("SELECT COUNT(*) FROM operator_ecr_publications WHERE status NOT IN "
            "('published','denied','expired','failed','uncertain') AND expires_at_epoch_ms>?",
            (now.unix_seconds * 1000,)).fetchone()[0] < MAX_ACTIVE_PUBLICATIONS)
        # Whole seconds are the reducer clock unit: round client expiry down,
        # never extend an expiring token by rounding it up.
        end = min(now.unix_seconds + ttl_seconds, binding["token_expires_at_epoch_ms"] // 1000)
        if binding["credential_expires_at_epoch_ms"] is not None:
            end = min(end, binding["credential_expires_at_epoch_ms"] // 1000)
        _need(end > now.unix_seconds)
        identifier = str(uuid.uuid4())
        conn.execute("INSERT INTO operator_ecr_publications "
            "(id,status,binding_json,manifest_digest,artifact_sha256,boot_id,created_at_epoch_ms,"
            "expires_at_epoch_ms,deadline_monotonic_ns) VALUES(?,'staging',?,?,?,?,?,?,?)",
            (identifier, canonical(binding), manifest_digest, artifact_sha256, _boot(), now.unix_seconds * 1000,
                end * 1000, now.monotonic_ns + (end - now.unix_seconds) * 1_000_000_000))
        row = _find(conn, identifier)
        _audit(db, conn, "created", row)
        return _public(row)


def require_client(principal_id, identifier, *, staging=False):
    """Recheck an already-authenticated client before a bounded artifact operation."""
    with _transaction() as (conn, db, reviewer, now):
        row = _find(conn, identifier)
        _live(conn, db, row, now)
        binding = _current(conn, row, now)
        _need(binding["principal_id"] == principal_id and (not staging or row["status"] == "staging"))
        return _public(row)


def status(identifier, actor):
    with _transaction() as (conn, db, reviewer, now):
        row = _find(conn, identifier)
        _need(actor in {reviewer, json.loads(row["binding_json"])["principal_id"]})
        return _public(row, now)


def list_publications(actor):
    with _transaction() as (conn, db, reviewer, now):
        rows = conn.execute("SELECT * FROM operator_ecr_publications ORDER BY created_at_epoch_ms DESC,id DESC LIMIT ?",
            (MAX_PUBLICATIONS,)).fetchall()
        return [_public(dict(row), now) for row in rows
            if actor == reviewer or json.loads(row["binding_json"])["principal_id"] == actor][:100]


def finalize_stage(identifier, sealed_image):
    """Caller keeps custody ownership here; no image bytes are verified inside SQL."""
    _need(type(sealed_image) is custody.SealedImage)
    image = sealed_image.image
    commitment = image.commitment()
    with _transaction() as (conn, db, reviewer, now):
        row = _find(conn, identifier)
        _live(conn, db, row, now)
        _current(conn, row, now)
        _need(row["status"] == "staging" and image.manifest.digest == row["manifest_digest"]
            and image.commitment_sha256 == row["artifact_sha256"])
        conn.execute("UPDATE operator_ecr_publications SET status='awaiting_review',artifact_json=?,revision=revision+1 "
            "WHERE id=? AND status='staging'", (canonical(commitment), identifier))
        _audit(db, conn, "staged", row)
        return _public(_find(conn, identifier))


def _review_digest(row):
    return _digest({"schema": "serverware.ecrPublicationReview/v1", "id": row["id"],
        "binding": json.loads(row["binding_json"]), "artifact": json.loads(row["artifact_json"]),
        "manifest_digest": row["manifest_digest"], "artifact_sha256": row["artifact_sha256"],
        "expires_at_epoch_ms": row["expires_at_epoch_ms"], "deadline_monotonic_ns": row["deadline_monotonic_ns"]})


def review(identifier, actor):
    with _transaction() as (conn, db, reviewer, now):
        _need(actor == reviewer)
        row = _find(conn, identifier)
        _live(conn, db, row, now)
        _current(conn, row, now)
        _need(row["status"] == "awaiting_review")
        receipt, digest = str(uuid.uuid4()), _review_digest(row)
        expiry = min(row["expires_at_epoch_ms"], now.unix_seconds * 1000 + 120_000)
        conn.execute("UPDATE operator_ecr_publications SET review_receipt_id=?,review_digest=?,"
            "review_expires_at_epoch_ms=? WHERE id=?", (receipt, digest, expiry, identifier))
        _audit(db, conn, "reviewed", row, actor, review_receipt_id=receipt, review_digest=digest)
        return {"publication": _public(_find(conn, identifier)), "review_receipt_id": receipt,
            "review_digest": digest, "review_expires_at_epoch_ms": expiry, "assurance": "host-trusted"}


def decide(identifier, actor, value):
    _need(type(value) is dict and set(value) == {"decision", "review_receipt_id", "review_digest", "note"}
        and value["decision"] in {"approve", "deny"})
    _identifier(value["review_receipt_id"])
    note = value["note"]
    _need(note is None or type(note) is str and len(note.encode("utf-8")) <= 500
        and all(ord(char) >= 32 and ord(char) != 127 for char in note))
    with _transaction() as (conn, db, reviewer, now):
        _need(actor == reviewer)
        row = _find(conn, identifier)
        _live(conn, db, row, now)
        _current(conn, row, now)
        _need(row["status"] == "awaiting_review" and row["review_receipt_id"] == value["review_receipt_id"]
            and row["review_digest"] == value["review_digest"] == _review_digest(row)
            and row["review_expires_at_epoch_ms"] > now.unix_seconds * 1000)
        state = "approved" if value["decision"] == "approve" else "denied"
        conn.execute("UPDATE operator_ecr_publications SET status=?,reviewer_id=?,decision_note=?,"
            "review_receipt_id=NULL,review_digest=NULL,review_expires_at_epoch_ms=NULL,revision=revision+1 WHERE id=?",
            (state, actor, note, identifier))
        _audit(db, conn, state, row, actor, review_digest=value["review_digest"])
        return _public(_find(conn, identifier))


def _scope(row):
    binding = json.loads(row["binding_json"])
    scope = binding["scope"]
    return planner.PublicationScope(protocol.Scope(scope["registry_id"], scope["region"], scope["repository_name"]),
        row["id"], binding["principal_id"], binding["route_id"], binding["credential_id"],
        binding["credential_generation"], binding["policy_hash"], scope["image_tag"])


def _deadline(row):
    return planner.Deadline(row["expires_at_epoch_ms"] // 1000, row["deadline_monotonic_ns"])


@dataclass(repr=False)
class _Held:
    image: custody.SealedImage
    snapshot: planner.Snapshot
    pending: planner.RequestPlan | None = None
    child_id: str | None = None


@dataclass(frozen=True, repr=False)
class Reservation:
    publication_id: str
    child_id: str
    action: str
    body: bytes
    request_sha256: str
    request_binding_sha256: str
    deadline: planner.Deadline
    binding: dict


def activate(identifier, sealed_image, *, principal_id=None):
    """Transfer the caller's newly recaptured custody only on successful activation."""
    _need(type(sealed_image) is custody.SealedImage)
    image, commitment = sealed_image.image, sealed_image.image.commitment()
    with _transaction() as (conn, db, reviewer, now):
        row = _find(conn, identifier)
        _live(conn, db, row, now)
        binding = _current(conn, row, now)
        _need(principal_id is None or principal_id == binding["principal_id"])
        _need(row["status"] in {"approved", "suspended"} and row["child_status"] not in _PENDING
            and row["reviewer_id"] == reviewer and commitment == json.loads(row["artifact_json"])
            and image.manifest.digest == row["manifest_digest"] and image.commitment_sha256 == row["artifact_sha256"])
        state = (planner.restore_checkpoint(image, _scope(row), row["checkpoint_json"].encode("utf-8"),
            clock=now, deadline=_deadline(row)) if row["checkpoint_json"] else
            planner.create(image, _scope(row), clock=now, deadline=_deadline(row)))
        checkpoint = planner.export_checkpoint(state).decode("utf-8")
        _need(state.status in {"fresh", "active"})
        conn.execute("UPDATE operator_ecr_publications SET status='active',checkpoint_json=?,owner_process=?,"
            "revision=revision+1 WHERE id=?", (checkpoint, _PROCESS, identifier))
        _audit(db, conn, "activated", row)
        conn.commit()  # Custody ownership changes only after durable activation.
        _drop(identifier)
        _HANDLES[identifier] = _Held(sealed_image, state)
        return _public(_find(conn, identifier))


def _match(binding, *, principal_id, route_id, credential_id, credential_generation, policy_hash):
    expected = dict(principal_id=principal_id, route_id=route_id, credential_id=credential_id,
        credential_generation=credential_generation, policy_hash=policy_hash)
    _need(all(binding[key] == value and type(binding[key]) is type(value) for key, value in expected.items()))


def reserve(identifier, *, child_id, request_binding_sha256, principal_id, route_id, credential_id,
        credential_generation, policy_hash, action, body):
    """Durably reserve before expensive byte comparison; never grants signing itself."""
    _need(type(body) is bytes and 0 < len(body) <= protocol.MAX_REQUEST_BYTES)
    _need(type(action) is str and action in {"BatchCheckLayerAvailability", "InitiateLayerUpload",
        "UploadLayerPart", "CompleteLayerUpload", "PutImage"})
    body_digest = "sha256:" + hashlib.sha256(body).hexdigest()
    child = _identifier(child_id)
    _need(type(request_binding_sha256) is str and _SHA.fullmatch(request_binding_sha256))
    wire = dict(principal_id=principal_id, route_id=route_id, credential_id=credential_id,
        credential_generation=credential_generation, policy_hash=policy_hash)
    with _transaction() as (conn, db, reviewer, now):
        row = _find(conn, identifier)
        _live(conn, db, row, now)
        binding = _current(conn, row, now)
        _match(binding, **wire)
        held = _HANDLES.get(identifier)
        _need(row["status"] == "active" and row["owner_process"] == _PROCESS and held is not None
            and held.pending is None and row["child_status"] not in _PENDING and row["attempts"] < MAX_ATTEMPTS)
        _need(conn.execute("SELECT 1 FROM operator_ecr_child_ids WHERE id=?", (child,)).fetchone() is None)
        conn.execute("INSERT INTO operator_ecr_child_ids VALUES(?,?,?)", (child, identifier, request_binding_sha256))
        conn.execute("UPDATE operator_ecr_publications SET child_id=?,child_action=?,child_status='preparing',"
            "child_request_sha256=?,child_binding_sha256=?,child_response_sha256=NULL,attempts=attempts+1,revision=revision+1 WHERE id=?",
            (child, action, body_digest, request_binding_sha256, identifier))
        _audit(db, conn, "reserved", row, child_id=child, action=action, request_sha256=body_digest)
    try:
        request = protocol.parse_request(scope=_scope(row).protocol_scope, action=action, body=body)
        state, proposed = planner.begin(held.snapshot, request, clock=_clock(), read_blob=held.image.read_blob)
        with _transaction() as (conn, db, reviewer, now):
            row = _find(conn, identifier)
            _live(conn, db, row, now)
            _match(_current(conn, row, now), **wire)
            _need(row["status"] == "active" and row["child_id"] == child and row["child_status"] == "preparing"
                and _HANDLES.get(identifier) is held and held.pending is None)
            conn.execute("UPDATE operator_ecr_publications SET child_status='reserved',revision=revision+1 WHERE id=?", (identifier,))
            conn.commit()
            held.snapshot, held.pending, held.child_id = state, proposed, child
            return Reservation(identifier, child, action, request.body, request.body_sha256,
                request_binding_sha256, state.deadline, binding)
    except BaseException:
        fail(child, publication_id=identifier, before_send=True, request_binding_sha256=request_binding_sha256, **wire)
        raise


def _child(conn, child_id):
    _identifier(child_id)
    row = conn.execute("SELECT * FROM operator_ecr_publications WHERE child_id=?", (child_id,)).fetchone()
    if row is None:
        raise PublicationNotFound()
    return dict(row)


@contextmanager
def signing_transaction(child_id, *, publication_id, request_binding_sha256, principal_id, route_id, credential_id,
        credential_generation, policy_hash):
    """Yield (SQLite connection, exact Reservation) for a pure opener and signer.

    Do not send upstream in this context. On normal exit the possible-send audit
    commits before the caller can return signed bytes. Never retry this lease.
    """
    with _transaction() as (conn, db, reviewer, now):
        row = _child(conn, child_id)
        _need(row["id"] == publication_id)
        _live(conn, db, row, now)
        binding = _current(conn, row, now)
        _match(binding, principal_id=principal_id, route_id=route_id, credential_id=credential_id,
            credential_generation=credential_generation, policy_hash=policy_hash)
        held = _HANDLES.get(row["id"])
        _need(row["status"] == "active" and row["child_status"] == "reserved" and row["owner_process"] == _PROCESS
            and held is not None and held.pending is not None and held.child_id == child_id
            and held.pending.request_sha256 == row["child_request_sha256"]
            and row["child_binding_sha256"] == request_binding_sha256)
        request = held.pending.request
        conn.execute("UPDATE operator_ecr_publications SET child_status='possible_send',revision=revision+1 WHERE id=?", (row["id"],))
        _audit(db, conn, "possible_send", row, child_id=child_id, action=request.action, request_sha256=request.body_sha256)
        yield conn, Reservation(row["id"], child_id, request.action, request.body,
            request.body_sha256, request_binding_sha256, held.snapshot.deadline, binding)


def finish(child_id, *, publication_id, status, body, request_binding_sha256, principal_id, route_id, credential_id,
        credential_generation, policy_hash):
    """Validate one correlated provider ACK and durably advance before release."""
    _need(type(status) is int and type(body) is bytes and len(body) <= protocol.MAX_RESPONSE_BYTES)
    wire = dict(publication_id=publication_id, request_binding_sha256=request_binding_sha256, principal_id=principal_id, route_id=route_id,
        credential_id=credential_id, credential_generation=credential_generation, policy_hash=policy_hash)
    with _transaction() as (conn, db, reviewer, now):
        row = _child(conn, child_id)
        _need(row["id"] == publication_id)
        _match(json.loads(row["binding_json"]), principal_id=principal_id, route_id=route_id,
            credential_id=credential_id, credential_generation=credential_generation, policy_hash=policy_hash)
        _need(row["child_binding_sha256"] == request_binding_sha256)
        _live(conn, db, row, now)
        held = _HANDLES.get(row["id"])
        _need(row["status"] == "active" and row["child_status"] == "possible_send" and held is not None
            and held.child_id == child_id and held.pending is not None)
        pending, snapshot = held.pending, held.snapshot
    # No SQL/publication lock is held while decoding a potentially large ACK.
    # The pending child remains durable and exclusively occupied throughout.
    try:
        response = protocol.parse_response(pending.request, status=status, body=body)
        state = planner.apply_response(snapshot, pending, response, clock=_clock())
        checkpoint = planner.export_checkpoint(state).decode("utf-8")
    except (ValueError, TypeError):
        return fail(child_id, **wire)
    with _transaction() as (conn, db, reviewer, now):
        row = _child(conn, child_id)
        _live(conn, db, row, now)
        _need(row["id"] == publication_id and row["status"] == "active" and row["child_status"] == "possible_send"
            and row["child_binding_sha256"] == request_binding_sha256 and _HANDLES.get(row["id"]) is held
            and held.child_id == child_id and held.pending is pending and held.snapshot is snapshot)
        authority_changed = False
        try:
            _current(conn, row, now)
        except (ValueError, RuntimeError):
            authority_changed = True
        # A validated ACK is evidence of an effect, not permission for the next
        # child. Preserve it even when revocation raced the provider response.
        # Final PutImage success remains a published image; intermediate success
        # records its ACK but closes the parent against all further dispatch.
        target = "published" if state.status == "published" else "failed" if authority_changed else "active"
        reason = "authority_changed_after_send" if authority_changed else None
        conn.execute("UPDATE operator_ecr_publications SET status=?,checkpoint_json=?,child_status='acknowledged',"
            "child_response_sha256=?,terminal_reason=?,revision=revision+1 WHERE id=?", (target, checkpoint,
                "sha256:" + hashlib.sha256(body).hexdigest(), reason, row["id"]))
        _audit(db, conn, "acknowledged", row, child_id=child_id, action=row["child_action"],
            request_sha256=row["child_request_sha256"], response_sha256="sha256:" + hashlib.sha256(body).hexdigest(),
            resulting_status=target, authority_changed=authority_changed)
        conn.commit()
        held.snapshot, held.pending, held.child_id = state, None, None
        if target in _TERMINAL:
            _drop(row["id"])
        return _public(_find(conn, row["id"]))


def fail(child_id, *, publication_id, request_binding_sha256, principal_id, route_id, credential_id,
        credential_generation, policy_hash, before_send=False):
    """Terminal child failure; caller assertion cannot downgrade possible-send."""
    with _transaction() as (conn, db, reviewer, now):
        row = _child(conn, child_id)
        _need(row["id"] == publication_id)
        _match(json.loads(row["binding_json"]), principal_id=principal_id, route_id=route_id,
            credential_id=credential_id, credential_generation=credential_generation, policy_hash=policy_hash)
        _need(row["child_binding_sha256"] == request_binding_sha256)
        if row["status"] in _TERMINAL:
            return _public(row)
        _need(row["child_status"] in _PENDING)
        proven_before_send = before_send is True and row["child_status"] in {"preparing", "reserved"}
        state = "failed" if proven_before_send or row["child_action"] == "BatchCheckLayerAvailability" else "uncertain"
        _terminal(conn, db, row, state, "request_failed_before_send" if proven_before_send else "request_outcome_unknown")
        return _public(_find(conn, row["id"]))
