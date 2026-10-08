"""Transactional operator catalog lifecycle, independent of native authority.

Only encrypted db.credentials stores provider secrets. Application verifiers are
hashes; raw client tokens are returned once and never retained here or in audit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import secrets
import time
import uuid

from serverware import operator_catalog_policy as policy
from serverware import operator_catalog_schema as schema
from serverware import operator_demo_store as store
from serverware.operator_catalog_inputs import (
    ApplicationInput, CredentialInput, RuleInput, TargetInput, RotateApplicationInput,
    MIN_TOKEN_LIFETIME_SECONDS, MAX_TOKEN_LIFETIME_SECONDS, DEFAULT_TOKEN_LIFETIME_SECONDS,
)
from serverware.operator_catalog_schema import CatalogConflict, CatalogIntegrityError

MAX_ACTIVE_RESOURCES = 32
MAX_RETAINED_RESOURCES = 1024
_RESULT_KEYS = {"credentials": "credential", "applications": "application", "access_rules": "access_rule"}
_COMMON_PUBLIC = ("id", "name", "created_at", "status", "revoked_at", "version")


class CatalogNotFound(Exception):
    """No catalog resource has this identifier."""


class CatalogLimitReached(Exception):
    def __init__(self, collection: str, reason: str):
        self.collection, self.reason = collection, reason
        super().__init__("operator catalog admission limit reached")


@dataclass
class _Change:
    resource: dict
    authority_changed: bool = False
    client_token: str | None = field(default=None, repr=False)
    affected_rule_ids: list[str] = field(default_factory=list)


def _state(conn) -> dict:
    row = conn.execute("SELECT policy_hash,sequence FROM operator_demo_policy WHERE singleton=1").fetchone()
    if row is None:
        raise CatalogIntegrityError("committed catalog policy unavailable")
    return dict(row)


def _active_rules(catalog: dict, key: str, identifier: str) -> list[dict]:
    return [row for row in catalog["access_rules"] if row["status"] == "active" and row[key] == identifier]


def _target(catalog: dict, collection: str, identifier: str) -> dict:
    row = next((row for row in catalog[collection] if row["id"] == identifier), None)
    if row is None:
        raise CatalogNotFound()
    if row["status"] != "active":
        raise CatalogConflict()
    return dict(row)


def _admit_create(conn, catalog: dict, collection: str) -> None:
    rows = catalog[collection]
    if sum(row["status"] == "active" for row in rows) >= MAX_ACTIVE_RESOURCES:
        raise CatalogLimitReached(collection, "active")
    if len(rows) + schema.retained_legacy_count(conn, collection) >= MAX_RETAINED_RESOURCES:
        raise CatalogLimitReached(collection, "retained")


def _policy_observation(state: dict, *, publication_failed: bool = False) -> dict:
    """Compare loaded authority to this snapshot AND the current committed hash."""
    loaded, current = None, None
    try:
        loaded = store.loaded_policy_hash()
        with store._require().connect() as conn:
            current = _state(conn)["policy_hash"]
    except Exception:
        # This read follows a successful commit too: never claim rollback or
        # lose the one-time token solely because gate observation is unavailable.
        pass
    return {"policy_hash": state["policy_hash"], "sequence": state["sequence"],
        "loaded_policy_hash": loaded, "activation": "active"
        if not publication_failed and loaded is not None and loaded == current == state["policy_hash"] else "pending"}


def _public(collection: str, record: dict, catalog: dict, observation: dict, now: int) -> dict:
    result = {key: record[key] for key in _COMMON_PUBLIC if key in record}
    loaded = observation["activation"] == "active"
    if collection == "credentials":
        result.update(auth_type=record["auth_type"], header_name=record["header_name"],
            active_rule_count=len(_active_rules(catalog, "credential_id", record["id"])))
    elif collection == "applications":
        count = len(_active_rules(catalog, "application_id", record["id"]))
        revoked = record["status"] == "revoked"
        expired = now >= record["token_expires_at_epoch_ms"]
        result.update(principal_id=record["principal_id"],
            token_expires_at_epoch_ms=record["token_expires_at_epoch_ms"],
            token_generation=record["token_version"],
            token_status="revoked" if revoked else "expired" if expired else "valid",
            access_status=("revoked" if loaded else "pending") if revoked else
                "unassigned" if not count else "active" if loaded and not expired else "pending",
            active_rule_count=count)
        if "token_rotated_at" in record:
            result["token_rotated_at"] = record["token_rotated_at"]
    else:
        for key in ("application_id", "credential_id", "route_id", "upstream_url", "methods",
                "request_fields", "response_fields", "query_keys", "allowed_headers"):
            result[key] = record[key]
        result.update(response_mode=record.get("response_mode", "projected_json"),
            enforcement=("revoked" if record["status"] == "revoked" else "active") if loaded else "pending")
    return result


def _mutate(payload, actor_id: str, collection: str, event: str, change) -> dict:
    db = store._require()
    publication_failed = False
    with store._LOCK, db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        schema.require_revision(conn, payload.expected_revision)
        state = _state(conn)
        if state["policy_hash"] != payload.expected_policy_hash:
            raise CatalogConflict()
        catalog = schema.read_catalog(conn)
        schema.validate_bindings(conn, catalog)
        changed = change(db, conn, catalog)
        schema.validate_bindings(conn)
        publication = policy.publish(conn) if changed.authority_changed else {**state, "changed": False}
        revision = schema.advance_revision(conn, payload.expected_revision)
        audit = {"resource_type": _RESULT_KEYS[collection], "resource_id": changed.resource["id"],
            "revision": revision, "policy_hash": publication["policy_hash"],
            "policy_sequence": publication["sequence"]}
        if collection == "applications":
            audit.update(token_generation=changed.resource["token_version"],
                token_expires_at_epoch_ms=changed.resource["token_expires_at_epoch_ms"])
        if collection == "access_rules":
            audit.update(application_id=changed.resource["application_id"], credential_id=changed.resource["credential_id"])
        if changed.affected_rule_ids:
            audit["affected_rule_ids"] = changed.affected_rule_ids
        db.append_audit_event(conn, event_type="operator_catalog." + event,
            actor_type="admin", actor_id=actor_id, event=audit)
        catalog = schema.read_catalog(conn)
        conn.commit()
        if publication["changed"]:
            try:
                store.materialize()
            except Exception:
                publication_failed = True
    observation = _policy_observation(publication, publication_failed=publication_failed)
    result = {_RESULT_KEYS[collection]: _public(collection, changed.resource, catalog, observation,
        time.time_ns() // 1_000_000), "revision": revision, "policy": observation}
    if changed.client_token is not None:
        result["client_token"] = changed.client_token
    if changed.affected_rule_ids:
        result["affected_rule_ids"] = changed.affected_rule_ids
    return result


def create_credential(payload: CredentialInput, actor_id: str) -> dict:
    def change(db, conn, catalog):
        _admit_create(conn, catalog, "credentials")
        subject = str(uuid.uuid4())
        credential = db.create_credential(payload.name, payload.auth_type, payload.secret,
            {"provider_id": "operator-demo", "provider_subject": subject,
             "secret_class": "bearerToken" if payload.auth_type == "bearer" else "customHeader"}, _connection=conn)
        record = {"id": credential["id"], "name": payload.name, "auth_type": payload.auth_type,
            "header_name": "Authorization" if payload.auth_type == "bearer" else payload.header_name,
            "provider_subject": subject, "created_at": db.iso_now(), "status": "active"}
        return _Change(schema.save_resource(conn, "credentials", record, create=True))
    return _mutate(payload, actor_id, "credentials", "credential.created", change)


def _new_token(lifetime: int) -> tuple[str, dict]:
    token = secrets.token_urlsafe(32)
    return token, {"token_sha256": "sha256:" + hashlib.sha256(token.encode("ascii")).hexdigest(),
        "token_expires_at_epoch_ms": time.time_ns() // 1_000_000 + lifetime * 1000}


def create_application(payload: ApplicationInput, actor_id: str) -> dict:
    def change(db, conn, catalog):
        _admit_create(conn, catalog, "applications")
        identifier = str(uuid.uuid4())
        token, verifier = _new_token(payload.token_lifetime_seconds)
        record = {"id": identifier, "name": payload.name, "principal_id": "agent:operator-demo:" + identifier,
            **verifier, "token_version": 1, "created_at": db.iso_now(), "status": "active"}
        return _Change(schema.save_resource(conn, "applications", record, create=True), client_token=token)
    return _mutate(payload, actor_id, "applications", "application.created", change)


def create_rule(payload: RuleInput, actor_id: str) -> dict:
    from serverware import operator_demo
    upstream, _ = operator_demo.origin(payload.upstream_url, target=True)
    if upstream not in operator_demo.settings()["allowed_upstreams"]:
        raise ValueError("destination is not deployment-allowlisted")

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "access_rules")
        _target(catalog, "applications", payload.application_id)
        _target(catalog, "credentials", payload.credential_id)
        identifier = str(uuid.uuid4())
        record = payload.model_dump(exclude={"expected_revision", "expected_policy_hash"})
        record.update(id=identifier, route_id="operator." + identifier, created_at=db.iso_now(), status="active")
        return _Change(schema.save_resource(conn, "access_rules", record, create=True), authority_changed=True)
    return _mutate(payload, actor_id, "access_rules", "access_rule.created", change)


def revoke_credential(payload: TargetInput, actor_id: str) -> dict:
    def change(db, conn, catalog):
        record = _target(catalog, "credentials", payload.id)
        if _active_rules(catalog, "credential_id", payload.id):
            raise CatalogConflict()
        if not db.delete_credential(payload.id, _connection=conn):
            raise CatalogIntegrityError("credential binding disappeared")
        record.update(status="revoked", revoked_at=db.iso_now())
        return _Change(schema.save_resource(conn, "credentials", record))
    return _mutate(payload, actor_id, "credentials", "credential.revoked", change)


def revoke_application(payload: TargetInput, actor_id: str) -> dict:
    def change(db, conn, catalog):
        record = _target(catalog, "applications", payload.id)
        rules = _active_rules(catalog, "application_id", payload.id)
        revoked_at = db.iso_now()
        for rule in rules:
            schema.save_resource(conn, "access_rules", {**rule, "status": "revoked", "revoked_at": revoked_at})
        record.update(status="revoked", revoked_at=revoked_at)
        return _Change(schema.save_resource(conn, "applications", record), authority_changed=bool(rules),
            affected_rule_ids=[rule["id"] for rule in rules])
    return _mutate(payload, actor_id, "applications", "application.revoked", change)


def rotate_application_token(payload: RotateApplicationInput, actor_id: str) -> dict:
    def change(db, conn, catalog):
        record = _target(catalog, "applications", payload.id)
        token, verifier = _new_token(payload.token_lifetime_seconds)
        record.update(verifier)
        record.update(token_version=record["token_version"] + 1, token_rotated_at=db.iso_now())
        return _Change(schema.save_resource(conn, "applications", record),
            authority_changed=bool(_active_rules(catalog, "application_id", payload.id)), client_token=token)
    return _mutate(payload, actor_id, "applications", "application.token_rotated", change)


def revoke_rule(payload: TargetInput, actor_id: str) -> dict:
    def change(db, conn, catalog):
        record = _target(catalog, "access_rules", payload.id)
        record.update(status="revoked", revoked_at=db.iso_now())
        return _Change(schema.save_resource(conn, "access_rules", record), authority_changed=True)
    return _mutate(payload, actor_id, "access_rules", "access_rule.revoked", change)


def catalog_status() -> dict:
    from serverware import operator_demo
    with store._require().connect() as conn:
        conn.execute("BEGIN")
        catalog = schema.read_catalog(conn)
        schema.validate_bindings(conn, catalog)
        state = _state(conn)
        limits = {collection: {"active": sum(row["status"] == "active" for row in catalog[collection]),
            "retained": len(catalog[collection]) + schema.retained_legacy_count(conn, collection),
            "active_max": MAX_ACTIVE_RESOURCES, "retained_max": MAX_RETAINED_RESOURCES} for collection in _RESULT_KEYS}
    observation = _policy_observation(state)
    now, settings = time.time_ns() // 1_000_000, operator_demo.settings()
    return {"schema": "serverware.operatorCatalog/v1", "mode": "operator-development",
        "productionReady": False, "hardwareVerified": False, "revision": catalog["revision"],
        "policy": observation, "proxy_url": settings["proxy_url"], "allowed_upstreams": settings["allowed_upstreams"],
        **{collection: [_public(collection, row, catalog, observation, now) for row in catalog[collection]]
           for collection in _RESULT_KEYS}, "limits": limits,
        "capabilities": {"credential_types": ["bearer", "header"], "response_modes": ["projected_json"], "oauth": False,
            "token_lifetime_seconds": {"min": MIN_TOKEN_LIFETIME_SECONDS, "max": MAX_TOKEN_LIFETIME_SECONDS,
                "default": DEFAULT_TOKEN_LIFETIME_SECONDS}}}
