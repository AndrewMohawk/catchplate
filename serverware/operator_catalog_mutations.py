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
from serverware import operator_catalog_timing as _catalog_timing
from serverware import operator_demo_store as store
from serverware.operator_catalog_inputs import (
    ApplicationInput, CredentialInput, RuleInput, TargetInput, RotateApplicationInput, GmailReadRuleInput,
    ReplaceCredentialKeyInput, ApplicationProxyAuthenticationInput,
    GithubTokenInput, GithubAppInput, GithubRuleInput, NpmTokenInput, NpmMetadataRuleInput, NpmPublishRuleInput, NpmInstallRuleInput,
    XAppBearerInput, XUsernameRuleInput,
    AlchemyKeyInput, AlchemyChainStatusRuleInput,
    AwsSigV4CredentialInput, ReplaceAwsSigV4CredentialInput,
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
    key_replacement: dict | None = None
    previous_proxy_authentication: str | None = None


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


def _catalog_observation(state: dict) -> tuple[dict, bool, bool, bool]:
    """One bounded gate read for this catalog response, never a shared cache.

    Managed mode retains its before/after configuration and binary checks.
    The final local read fences capability displays to the serialized
    catalog's policy, not merely to whichever newer policy the gate reports.
    Mutation receipts and admission keep their separate fresh observers.
    """
    loaded, current = None, None
    x_available, alchemy_available, npm_install_available = False, False, False
    try:
        from serverware import operator_catalog_x, operator_catalog_alchemy, operator_catalog_npm_install
        from serverware import operator_google_managed_config as managed
        from serverware import operator_publication as publication
        publication.assert_not_held()
        if managed.enabled():
            from serverware import operator_google_managed_readiness as readiness
            observed = readiness.observe_catalog()
            if observed["ready"] is True:
                loaded = observed["loaded_policy_hash"]
                x_available, alchemy_available = observed["x_available"], observed["alchemy_available"]
                npm_install_available = observed["npm_install_available"]
        else:
            observed = store.loaded_gate_status()
            if type(observed) is dict and observed.get("ok") is True:
                loaded = observed["policy_hash"]
                x_available = operator_catalog_x.gate_descriptor_matches(observed.get("operator_x_app_read"))
                alchemy_available = operator_catalog_alchemy.gate_descriptor_matches(observed.get("operator_alchemy_rpc_read"))
                npm_install_available = operator_catalog_npm_install.gate_descriptor_matches(observed.get("operator_npm_install"))
        # Starts only after HTTP and any managed snapshots have closed.
        with store._require().metadata_connection() as conn:
            current = _state(conn)["policy_hash"]
    except Exception:
        current = None
        x_available, alchemy_available, npm_install_available = False, False, False
    active = loaded is not None and loaded == current == state["policy_hash"]
    return ({"policy_hash": state["policy_hash"], "sequence": state["sequence"],
        "loaded_policy_hash": loaded, "activation": "active" if active else "pending"},
        active and x_available, active and alchemy_available, active and npm_install_available)


def _static_generations(conn, catalog: dict) -> dict[str, int | None]:
    """Core generations from the SAME catalog snapshot, never a lease/decrypt."""
    result = {}
    for record in catalog["credentials"]:
        if record["auth_type"] not in {"bearer", "header", "aws_sigv4_v1"}:
            continue
        if record["status"] == "revoked":
            result[record["id"]] = None
            continue
        core = conn.execute(
            "SELECT c.credential_version,g.last_version FROM credentials c "
            "LEFT JOIN credential_generations g ON g.credential_id=c.id WHERE c.id=?",
            (record["id"],)).fetchone()
        if (core is None or type(core["credential_version"]) is not int
                or not 1 <= core["credential_version"] <= 9_007_199_254_740_991
                or type(core["last_version"]) is not int
                or core["last_version"] != core["credential_version"]):
            raise CatalogIntegrityError("static credential generation binding refused")
        result[record["id"]] = core["credential_version"]
    return result


def _public(collection: str, record: dict, catalog: dict, observation: dict, now: int,
        static_generations: dict | None = None) -> dict:
    result = {key: record[key] for key in _COMMON_PUBLIC if key in record}
    loaded = observation["activation"] == "active"
    if collection == "credentials":
        result.update(auth_type=record["auth_type"], header_name=record["header_name"],
            active_rule_count=len(_active_rules(catalog, "credential_id", record["id"])))
        if record["auth_type"] == "google_oauth":
            from serverware import operator_catalog_google
            result.update(operator_catalog_google.public_fields(record))
        elif static_generations is not None:
            result["credential_generation"] = static_generations[record["id"]]
            if "key_replaced_at" in record:
                result["key_replaced_at"] = record["key_replaced_at"]
        if "connection_type" in record:
            from serverware import operator_catalog_github, operator_catalog_npm, operator_catalog_x, operator_catalog_alchemy
            from serverware import operator_catalog_aws
            from serverware import operator_github_app
            schema.validate_static_connection(record)
            providers = {operator_catalog_github.CONNECTION: "github",
                operator_catalog_npm.CONNECTION: "npm", operator_catalog_x.CONNECTION: "x",
                operator_catalog_alchemy.CONNECTION: "alchemy", operator_catalog_aws.CONNECTION: "aws",
                operator_github_app.CONNECTION: "github"}
            result.update(connection_type=record["connection_type"], provider_id=providers[record["connection_type"]])
            if record["connection_type"] == operator_catalog_aws.CONNECTION:
                result.update(operator_catalog_aws.public_fields(record, now))
            if record["connection_type"] == operator_github_app.CONNECTION:
                from copy import deepcopy
                result["github_app"] = deepcopy(record["github_app"])
    elif collection == "applications":
        count = len(_active_rules(catalog, "application_id", record["id"]))
        revoked = record["status"] == "revoked"
        expired = now >= record["token_expires_at_epoch_ms"]
        result.update(principal_id=record["principal_id"],
            proxy_authentication=schema.application_proxy_authentication(record),
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
            credential_input=record.get("credential_input", "insert"),
            enforcement=("revoked" if record["status"] == "revoked" else "active") if loaded else "pending")
        if result["credential_input"] == "replace_exact":
            result["placeholder"] = record["placeholder"]
        if "request_body_mode" in record:
            result["request_body_mode"] = record["request_body_mode"]
        from serverware import operator_catalog_github, operator_catalog_gmail, operator_catalog_npm, operator_catalog_npm_publish, operator_catalog_x, operator_catalog_alchemy
        from serverware import operator_catalog_npm_install
        if operator_catalog_npm_install.selected(record):
            result.update(operator_catalog_npm_install.public_fields(record))
        elif operator_catalog_alchemy.selected(record):
            result.update(operator_catalog_alchemy.public_fields(record))
        elif operator_catalog_x.selected(record):
            result.update(operator_catalog_x.public_fields(record))
        elif operator_catalog_npm_publish.selected(record):
            result.update(operator_catalog_npm_publish.public_fields(record))
        elif operator_catalog_npm.selected(record):
            result.update(operator_catalog_npm.public_fields(record))
        elif operator_catalog_github.selected(record):
            result.update(operator_catalog_github.public_fields(record))
        elif operator_catalog_gmail.selected(record):
            result.update(operator_catalog_gmail.public_fields(record))
    return result


def _mutate(payload, actor_id: str, collection: str, event: str, change) -> dict:
    db = store._require()
    timing = _catalog_timing.current()
    _catalog_timing.mark(timing, "publication_wait")
    with store.operator_publication.exclusive():
        _catalog_timing.mark(timing, "publication_acquired")
        with db.connect() as conn:
            _catalog_timing.mark(timing, "sqlite_open")
            conn.execute("BEGIN IMMEDIATE")
            _catalog_timing.mark(timing, "sqlite_begin")
            schema.require_revision(conn, payload.expected_revision)
            state = _state(conn)
            if state["policy_hash"] != payload.expected_policy_hash:
                raise CatalogConflict()
            catalog = schema.read_catalog(conn)
            schema.validate_bindings(conn, catalog)
            _catalog_timing.mark(timing, "bindings_validated")
            changed = change(db, conn, catalog)
            _catalog_timing.mark(timing, "change_done")
            schema.validate_bindings(conn)
            publication = policy.publish(conn) if changed.authority_changed else {**state, "changed": False}
            if changed.authority_changed:
                _catalog_timing.mark(timing, "policy_published")
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
            if changed.key_replacement is not None:
                audit.update({key: changed.key_replacement[key] for key in
                    ("previous_credential_generation", "credential_generation")})
            if changed.previous_proxy_authentication is not None:
                audit.update(previous_proxy_authentication=changed.previous_proxy_authentication,
                    proxy_authentication=schema.application_proxy_authentication(changed.resource),
                    affected_rule_ids=changed.affected_rule_ids)
            db.append_audit_event(conn, event_type="operator_catalog." + event,
                actor_type="admin", actor_id=actor_id, event=audit)
            _catalog_timing.mark(timing, "audit_appended")
            catalog = schema.read_catalog(conn)
            static_generations = _static_generations(conn, catalog)
            _catalog_timing.mark(timing, "commit_started")
            conn.commit()
            _catalog_timing.mark(timing, "commit_done")
            if publication["changed"]:
                _catalog_timing.mark(timing, "materialize_started")
                try:
                    store.materialize()
                    _catalog_timing.mark(timing, "materialize_done")
                except Exception:
                    # The commit remains authoritative; readiness is observed by
                    # a later catalog read, never asserted by this mutation receipt.
                    pass
    _catalog_timing.mark(timing, "publication_released")
    replacement_receipt = None
    if changed.key_replacement is not None:
        # COMMIT and all publication/DB ownership ended. This clears only this
        # Python process's cache; issued Rust leases and in-flight work survive.
        cache_invalidation = "local_unconfirmed"
        try:
            from serverware import runtime
            runtime.invalidate_secret_leases(changed.resource["id"])
            cache_invalidation = "local_completed"
        except Exception:
            pass  # Durable replacement remains committed; never claim rollback.
        replacement_receipt = {key: changed.key_replacement[key] for key in
            ("previous_credential_generation", "credential_generation")}
        replacement_receipt.update(cache_invalidation=cache_invalidation, in_flight_requests="not_recalled")
    # Acknowledge the captured durable result without a postcommit network or
    # database observation. Only a fresh catalog read may confirm gate loading;
    # even successful materialization is not evidence of proxy enforcement.
    observation = {"policy_hash": publication["policy_hash"], "sequence": publication["sequence"],
        "loaded_policy_hash": None, "activation": "pending"}
    result = {_RESULT_KEYS[collection]: _public(collection, changed.resource, catalog, observation,
        time.time_ns() // 1_000_000, static_generations), "revision": revision, "policy": observation}
    if replacement_receipt is not None:
        result["key_replacement"] = replacement_receipt
    if changed.client_token is not None:
        result["client_token"] = changed.client_token
    if changed.affected_rule_ids:
        result["affected_rule_ids"] = changed.affected_rule_ids
    _catalog_timing.mark(timing, "receipt_ready")
    return result


def create_credential(payload: CredentialInput, actor_id: str) -> dict:
    def change(db, conn, catalog):
        _admit_create(conn, catalog, "credentials")
        subject = str(uuid.uuid4())
        credential = db.create_credential(payload.name, payload.auth_type, payload.secret,
            {"provider_id": "operator-demo", "provider_subject": subject,
             "secret_class": "bearerToken" if payload.auth_type == "bearer" else "customHeader",
             **({"injection_name": payload.header_name} if payload.auth_type == "header" else {})}, _connection=conn)
        record = {"id": credential["id"], "name": payload.name, "auth_type": payload.auth_type,
            "header_name": "Authorization" if payload.auth_type == "bearer" else payload.header_name,
            "provider_subject": subject, "created_at": db.iso_now(), "status": "active"}
        return _Change(schema.save_resource(conn, "credentials", record, create=True))
    return _mutate(payload, actor_id, "credentials", "credential.created", change)


def create_github_credential(payload: GithubTokenInput, actor_id: str) -> dict:
    from serverware import operator_catalog_github as github

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "credentials")
        subject = str(uuid.uuid4())
        credential = db.create_credential(payload.name, "bearer", payload.secret,
            {"provider_id": "operator-demo", "provider_subject": subject,
                "secret_class": "bearerToken", "connection_type": github.CONNECTION}, _connection=conn)
        record = {"id": credential["id"], "name": payload.name, "auth_type": "bearer",
            "header_name": "Authorization", "connection_type": github.CONNECTION,
            "provider_subject": subject, "created_at": db.iso_now(), "status": "active"}
        return _Change(schema.save_resource(conn, "credentials", record, create=True))
    return _mutate(payload, actor_id, "credentials", "credential.github_token_created", change)


def create_aws_credential(payload: AwsSigV4CredentialInput, actor_id: str) -> dict:
    from serverware import operator_catalog_aws as aws

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "credentials")
        credential = db.create_operator_aws_credential(conn, name=payload.name, secret=aws.encode_secret(payload))
        metadata = credential["metadata"]
        record = {"id": credential["id"], "name": payload.name, "auth_type": aws.KIND,
            "header_name": None, "connection_type": aws.CONNECTION,
            "provider_subject": metadata["provider_subject"], "credential_kind": metadata["credential_kind"],
            "expires_at": metadata["expires_at"], "created_at": db.iso_now(), "status": "active"}
        return _Change(schema.save_resource(conn, "credentials", record, create=True))
    return _mutate(payload, actor_id, "credentials", "credential.aws_sigv4_created", change)


def create_github_app_credential(payload: GithubAppInput, actor_id: str) -> dict:
    from serverware import operator_github_app as apps, operator_catalog_github as github, operator_demo
    apps.require_runtime()
    if github.ORIGIN not in operator_demo.settings()["allowed_upstreams"]:
        raise ValueError("GitHub destination is not deployment-allowlisted")
    # Reject stale submissions before provider contact; recheck the same CAS in
    # the ordinary mutation owner after all bounded network work has finished.
    db = store._require()
    with store.operator_publication.exclusive():
        with db.metadata_connection() as conn:
            conn.execute("BEGIN")
            schema.require_revision(conn, payload.expected_revision)
            if _state(conn)["policy_hash"] != payload.expected_policy_hash:
                raise CatalogConflict()
            catalog = schema.read_catalog(conn)
            schema.validate_bindings(conn, catalog)
            _admit_create(conn, catalog, "credentials")
    prepared = apps.verify_connection(payload)
    subject = str(uuid.uuid4())
    metadata = apps.metadata(prepared.public, subject)

    def change(db, conn, catalog):
        apps.require_runtime()
        _admit_create(conn, catalog, "credentials")
        credential = db.create_operator_github_app_credential(conn, name=payload.name,
            secret=prepared.secret, metadata=metadata)
        record = {"id": credential["id"], "name": payload.name, "auth_type": "bearer",
            "header_name": "Authorization", "connection_type": apps.CONNECTION,
            "provider_subject": subject, "github_app": prepared.public,
            "created_at": db.iso_now(), "status": "active"}
        return _Change(schema.save_resource(conn, "credentials", record, create=True))
    result = _mutate(payload, actor_id, "credentials", "credential.github_app_created", change)
    # Memory-only optimization AFTER commit. Failure must not hide the saved
    # receipt; first dispatch can independently obtain its scoped token.
    try:
        apps.seed_committed({"id": result["credential"]["id"], "kind": "bearer",
            "credential_version": result["credential"]["credential_generation"], "metadata": metadata}, prepared)
    except Exception:
        pass
    return result


def replace_aws_credential(payload: ReplaceAwsSigV4CredentialInput, actor_id: str) -> dict:
    from serverware import operator_catalog_aws as aws

    def change(db, conn, catalog):
        record = _target(catalog, "credentials", payload.id)
        if not aws.selected(record):
            raise CatalogConflict()
        aws.validate_credential(record)
        receipt = db.replace_operator_aws_credential_if_version(conn, payload.id,
            expected_version=payload.expected_credential_generation, secret=aws.encode_secret(payload))
        if receipt is None:
            raise CatalogConflict()
        record.update(credential_kind=payload.credential_kind, expires_at=payload.expires_at,
            key_replaced_at=receipt["key_replaced_at"])
        return _Change(schema.save_resource(conn, "credentials", record), key_replacement=receipt)
    return _mutate(payload, actor_id, "credentials", "credential.aws_sigv4_replaced", change)


def replace_credential_key(payload: ReplaceCredentialKeyInput, actor_id: str) -> dict:
    def change(db, conn, catalog):
        record = _target(catalog, "credentials", payload.id)
        if record["auth_type"] not in {"bearer", "header"}:
            raise CatalogConflict()
        from serverware import operator_github_app
        if record.get("connection_type") == operator_github_app.CONNECTION:
            raise CatalogConflict()
        from serverware import operator_catalog_github, operator_catalog_npm, operator_catalog_x, operator_catalog_alchemy
        if schema.validate_static_connection(record):
            providers = {item.CONNECTION: item for item in
                (operator_catalog_github, operator_catalog_npm, operator_catalog_x, operator_catalog_alchemy)}
            provider = providers[record["connection_type"]]
            provider.validate_token(payload.secret)
        receipt = db.replace_operator_static_credential_secret_if_version(conn, payload.id,
            expected_version=payload.expected_credential_generation, secret=payload.secret)
        if receipt is None:
            raise CatalogConflict()
        record["key_replaced_at"] = receipt["key_replaced_at"]
        return _Change(schema.save_resource(conn, "credentials", record), key_replacement=receipt)
    return _mutate(payload, actor_id, "credentials", "credential.key_replaced", change)


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
        if "proxy_authentication" in payload.model_fields_set:
            record["proxy_authentication"] = payload.proxy_authentication
        return _Change(schema.save_resource(conn, "applications", record, create=True), client_token=token)
    return _mutate(payload, actor_id, "applications", "application.created", change)


def create_rule(payload: RuleInput, actor_id: str) -> dict:
    from serverware import operator_demo, operator_catalog_npm_publish, operator_catalog_npm_install
    upstream, _ = operator_demo.origin(payload.upstream_url, target=True)
    if upstream not in operator_demo.settings()["allowed_upstreams"]:
        raise ValueError("destination is not deployment-allowlisted")

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "access_rules")
        _target(catalog, "applications", payload.application_id)
        credential = _target(catalog, "credentials", payload.credential_id)
        identifier = str(uuid.uuid4())
        record = payload.model_dump(exclude={"expected_revision", "expected_policy_hash"})
        if "request_body_mode" not in payload.model_fields_set:
            record.pop("request_body_mode", None)
        if payload.credential_input == "insert":
            record.pop("placeholder", None)
        try:
            schema.rule_credential_header(record, credential)
            schema.rule_request_body_mode(record, credential)
        except CatalogIntegrityError:
            raise ValueError("rule content or credential input is incompatible with the selected credential") from None
        record.update(id=identifier, route_id="operator." + identifier, created_at=db.iso_now(), status="active")
        operator_catalog_npm_publish.admit_rule(record, catalog)
        operator_catalog_npm_install.admit_rule(record, catalog)
        return _Change(schema.save_resource(conn, "access_rules", record, create=True), authority_changed=True)
    return _mutate(payload, actor_id, "access_rules", "access_rule.created", change)


def create_gmail_rule(payload: GmailReadRuleInput, actor_id: str) -> dict:
    from serverware import operator_catalog_gmail as gmail
    from serverware import operator_catalog_google, operator_catalog_oauth_profile, operator_demo
    profile = operator_catalog_oauth_profile.require_profile()
    if gmail.ORIGIN not in operator_demo.settings()["allowed_upstreams"]:
        raise ValueError("Gmail destination is not deployment-allowlisted")

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "access_rules")
        _target(catalog, "applications", payload.application_id)
        credential = _target(catalog, "credentials", payload.credential_id)
        record = gmail.record_fields(payload)
        try:
            schema.rule_credential_header(record, credential)
            operator_catalog_google.validate_rule(record, credential, profile)
        except CatalogIntegrityError:
            raise ValueError("Gmail bundle requires a compatible connected account and input mode") from None
        identifier = str(uuid.uuid4())
        record.update(id=identifier, route_id="operator." + identifier, created_at=db.iso_now(), status="active")
        return _Change(schema.save_resource(conn, "access_rules", record, create=True), authority_changed=True)
    return _mutate(payload, actor_id, "access_rules", "access_rule.created", change)


def create_github_rule(payload: GithubRuleInput, actor_id: str) -> dict:
    from serverware import operator_catalog_github as github, operator_demo
    if github.ORIGIN not in operator_demo.settings()["allowed_upstreams"]:
        raise ValueError("GitHub destination is not deployment-allowlisted")

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "access_rules")
        _target(catalog, "applications", payload.application_id)
        credential = _target(catalog, "credentials", payload.credential_id)
        record = github.record_fields(payload)
        try:
            github.validate_rule(record, credential)
            schema.rule_credential_header(record, credential)
        except CatalogIntegrityError:
            raise ValueError("GitHub preset requires a GitHub token connection") from None
        identifier = str(uuid.uuid4())
        record.update(id=identifier, route_id="operator." + identifier, created_at=db.iso_now(), status="active")
        return _Change(schema.save_resource(conn, "access_rules", record, create=True), authority_changed=True)
    return _mutate(payload, actor_id, "access_rules", "access_rule.github_created", change)


def create_x_credential(payload: XAppBearerInput, actor_id: str) -> dict:
    from serverware import operator_catalog_x as x
    x.require_available(payload.expected_policy_hash)

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "credentials")
        subject = str(uuid.uuid4())
        credential = db.create_credential(payload.name, "bearer", payload.secret,
            {"provider_id": "operator-demo", "provider_subject": subject,
                "secret_class": "bearerToken", "connection_type": x.CONNECTION}, _connection=conn)
        record = {"id": credential["id"], "name": payload.name, "auth_type": "bearer",
            "header_name": "Authorization", "connection_type": x.CONNECTION,
            "provider_subject": subject, "created_at": db.iso_now(), "status": "active"}
        return _Change(schema.save_resource(conn, "credentials", record, create=True))
    return _mutate(payload, actor_id, "credentials", "credential.x_app_bearer_created", change)


def create_x_rule(payload: XUsernameRuleInput, actor_id: str) -> dict:
    from serverware import operator_catalog_x as x, operator_demo
    if x.ORIGIN not in operator_demo.settings()["allowed_upstreams"]:
        raise ValueError("X destination is not deployment-allowlisted")
    x.require_available(payload.expected_policy_hash)

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "access_rules")
        record = x.record_fields(payload)
        x.admit_rule(record, catalog)
        _target(catalog, "applications", payload.application_id)
        credential = _target(catalog, "credentials", payload.credential_id)
        try:
            x.validate_rule(record, credential)
            schema.rule_credential_header(record, credential)
        except CatalogIntegrityError:
            raise ValueError("X username preset requires an X app bearer connection") from None
        identifier = str(uuid.uuid4())
        record.update(id=identifier, route_id="operator." + identifier, created_at=db.iso_now(), status="active")
        return _Change(schema.save_resource(conn, "access_rules", record, create=True), authority_changed=True)
    return _mutate(payload, actor_id, "access_rules", "access_rule.x_username_created", change)


def create_alchemy_credential(payload: AlchemyKeyInput, actor_id: str) -> dict:
    from serverware import operator_catalog_alchemy as alchemy
    alchemy.require_available(payload.expected_policy_hash)

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "credentials")
        subject = str(uuid.uuid4())
        credential = db.create_credential(payload.name, "bearer", payload.secret,
            {"provider_id": "operator-demo", "provider_subject": subject,
                "secret_class": "bearerToken", "connection_type": alchemy.CONNECTION}, _connection=conn)
        record = {"id": credential["id"], "name": payload.name, "auth_type": "bearer",
            "header_name": "Authorization", "connection_type": alchemy.CONNECTION,
            "provider_subject": subject, "created_at": db.iso_now(), "status": "active"}
        return _Change(schema.save_resource(conn, "credentials", record, create=True))
    return _mutate(payload, actor_id, "credentials", "credential.alchemy_key_created", change)


def create_alchemy_rule(payload: AlchemyChainStatusRuleInput, actor_id: str) -> dict:
    from serverware import operator_catalog_alchemy as alchemy, alchemy_rpc_read, operator_demo
    if alchemy_rpc_read.origin(payload.chain) not in operator_demo.settings()["allowed_upstreams"]:
        raise ValueError("Alchemy destination is not deployment-allowlisted")
    alchemy.require_available(payload.expected_policy_hash)

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "access_rules")
        record = alchemy.record_fields(payload)
        alchemy.admit_rule(record, catalog)
        _target(catalog, "applications", payload.application_id)
        credential = _target(catalog, "credentials", payload.credential_id)
        try:
            alchemy.validate_rule(record, credential)
            schema.rule_credential_header(record, credential)
        except CatalogIntegrityError:
            raise ValueError("Alchemy chain-status preset requires an Alchemy key connection") from None
        identifier = str(uuid.uuid4())
        record.update(id=identifier, route_id="operator." + identifier, created_at=db.iso_now(), status="active")
        return _Change(schema.save_resource(conn, "access_rules", record, create=True), authority_changed=True)
    return _mutate(payload, actor_id, "access_rules", "access_rule.alchemy_chain_status_created", change)


def create_npm_credential(payload: NpmTokenInput, actor_id: str) -> dict:
    from serverware import operator_catalog_npm as npm

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "credentials")
        subject = str(uuid.uuid4())
        credential = db.create_credential(payload.name, "bearer", payload.secret,
            {"provider_id": "operator-demo", "provider_subject": subject,
                "secret_class": "bearerToken", "connection_type": npm.CONNECTION}, _connection=conn)
        record = {"id": credential["id"], "name": payload.name, "auth_type": "bearer",
            "header_name": "Authorization", "connection_type": npm.CONNECTION,
            "provider_subject": subject, "created_at": db.iso_now(), "status": "active"}
        return _Change(schema.save_resource(conn, "credentials", record, create=True))
    return _mutate(payload, actor_id, "credentials", "credential.npm_token_created", change)


def create_npm_rule(payload: NpmMetadataRuleInput, actor_id: str) -> dict:
    from serverware import operator_catalog_npm as npm, operator_catalog_npm_publish, operator_demo
    if npm.ORIGIN not in operator_demo.settings()["allowed_upstreams"]:
        raise ValueError("npm registry is not deployment-allowlisted")

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "access_rules")
        _target(catalog, "applications", payload.application_id)
        credential = _target(catalog, "credentials", payload.credential_id)
        record = npm.record_fields(payload)
        try:
            npm.validate_rule(record, credential)
            schema.rule_credential_header(record, credential)
        except CatalogIntegrityError:
            raise ValueError("npm metadata preset requires an npm token connection") from None
        operator_catalog_npm_publish.admit_rule(record, catalog)
        from serverware import operator_catalog_npm_install
        operator_catalog_npm_install.admit_rule(record, catalog)
        identifier = str(uuid.uuid4())
        record.update(id=identifier, route_id="operator." + identifier, created_at=db.iso_now(), status="active")
        return _Change(schema.save_resource(conn, "access_rules", record, create=True), authority_changed=True)
    return _mutate(payload, actor_id, "access_rules", "access_rule.npm_metadata_created", change)


def create_npm_publish_rule(payload: NpmPublishRuleInput, actor_id: str) -> dict:
    from serverware import operator_catalog_npm_publish as npm, operator_demo
    if npm.ORIGIN not in operator_demo.settings()["allowed_upstreams"]:
        raise ValueError("npm registry is not deployment-allowlisted")

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "access_rules")
        _target(catalog, "applications", payload.application_id)
        credential = _target(catalog, "credentials", payload.credential_id)
        record = npm.record_fields(payload)
        try:
            npm.validate_rule(record, credential)
            schema.rule_credential_header(record, credential)
        except CatalogIntegrityError:
            raise ValueError("npm publish preset requires an npm token connection") from None
        npm.admit_rule(record, catalog)
        from serverware import operator_catalog_npm_install
        operator_catalog_npm_install.admit_rule(record, catalog)
        identifier = str(uuid.uuid4())
        record.update(id=identifier, route_id="operator." + identifier, created_at=db.iso_now(), status="active")
        return _Change(schema.save_resource(conn, "access_rules", record, create=True), authority_changed=True)
    return _mutate(payload, actor_id, "access_rules", "access_rule.npm_publish_created", change)


def create_npm_install_rule(payload: NpmInstallRuleInput, actor_id: str) -> dict:
    from serverware import operator_catalog_npm_install as npm
    npm.require_available(payload.expected_policy_hash)

    def change(db, conn, catalog):
        _admit_create(conn, catalog, "access_rules")
        _target(catalog, "applications", payload.application_id)
        credential = _target(catalog, "credentials", payload.credential_id)
        record = npm.record_fields(payload)
        npm.admit_rule(record, catalog)
        try:
            npm.validate_rule(record, credential)
            schema.rule_credential_header(record, credential)
        except CatalogIntegrityError:
            raise ValueError("npm install preset requires an npm token connection") from None
        identifier = str(uuid.uuid4())
        record.update(id=identifier, route_id="operator." + identifier, created_at=db.iso_now(), status="active")
        return _Change(schema.save_resource(conn, "access_rules", record, create=True), authority_changed=True)
    return _mutate(payload, actor_id, "access_rules", "access_rule.npm_install_created", change)


def revoke_credential(payload: TargetInput, actor_id: str) -> dict:
    def change(db, conn, catalog):
        record = _target(catalog, "credentials", payload.id)
        if record.get("auth_type") == "google_oauth":
            # A shared OAuth grant needs provider-aware disconnect and retained
            # cleanup; the static deletion endpoint cannot substitute for it.
            raise CatalogConflict()
        if _active_rules(catalog, "credential_id", payload.id):
            raise CatalogConflict()
        from serverware import operator_catalog_aws as aws
        from serverware import operator_github_app
        removed = (db.delete_operator_aws_credential(conn, payload.id) if aws.selected(record)
            else db.delete_operator_github_app_credential(conn, payload.id)
                if record.get("connection_type") == operator_github_app.CONNECTION
            else db.delete_credential(payload.id, _connection=conn))
        if not removed:
            raise CatalogIntegrityError("credential binding disappeared")
        record.update(status="revoked", revoked_at=db.iso_now())
        return _Change(schema.save_resource(conn, "credentials", record))
    result = _mutate(payload, actor_id, "credentials", "credential.revoked", change)
    from serverware import operator_github_app
    operator_github_app.forget(payload.id)
    return result


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


def set_application_proxy_authentication(payload: ApplicationProxyAuthenticationInput, actor_id: str) -> dict:
    """Explicit transport permission change; never rotate or renew the token."""
    def change(db, conn, catalog):
        record = _target(catalog, "applications", payload.id)
        previous = schema.application_proxy_authentication(record)
        if previous == payload.proxy_authentication:
            raise CatalogConflict()
        rules = _active_rules(catalog, "application_id", payload.id)
        record["proxy_authentication"] = payload.proxy_authentication
        return _Change(schema.save_resource(conn, "applications", record), authority_changed=bool(rules),
            affected_rule_ids=[rule["id"] for rule in rules], previous_proxy_authentication=previous)
    return _mutate(payload, actor_id, "applications", "application.proxy_authentication_changed", change)


def revoke_rule(payload: TargetInput, actor_id: str) -> dict:
    def change(db, conn, catalog):
        record = _target(catalog, "access_rules", payload.id)
        record.update(status="revoked", revoked_at=db.iso_now())
        return _Change(schema.save_resource(conn, "access_rules", record), authority_changed=True)
    return _mutate(payload, actor_id, "access_rules", "access_rule.revoked", change)


def catalog_status() -> dict:
    from serverware import operator_catalog_activity, operator_catalog_capabilities, operator_catalog_github, operator_catalog_gmail, operator_catalog_npm, operator_catalog_npm_publish, operator_catalog_x, operator_catalog_alchemy, operator_demo
    from serverware import operator_catalog_aws
    from serverware import operator_github_app
    with store._require().connect() as conn:
        conn.execute("BEGIN")
        catalog = schema.read_catalog(conn)
        schema.validate_bindings(conn, catalog)
        static_generations = _static_generations(conn, catalog)
        google_oauth = operator_catalog_capabilities.google_oauth(conn)
        google_disconnect = operator_catalog_capabilities.google_disconnect(conn)
        google_reauthorization = operator_catalog_capabilities.google_reauthorization(conn)
        operation_bundles = operator_catalog_gmail.capabilities(conn)
        state = _state(conn)
        limits = {collection: {"active": sum(row["status"] == "active" for row in catalog[collection]),
            "retained": len(catalog[collection]) + schema.retained_legacy_count(conn, collection),
            "active_max": MAX_ACTIVE_RESOURCES, "retained_max": MAX_RETAINED_RESOURCES} for collection in _RESULT_KEYS}
        observed_activity = operator_catalog_activity.project(
            conn, catalog, observed_at_epoch_ms=time.time_ns() // 1_000_000)
    observation, x_available, alchemy_available, npm_install_available = _catalog_observation(state)
    now, settings = time.time_ns() // 1_000_000, operator_demo.settings()
    from serverware import operator_catalog_npm_install
    return {"schema": "serverware.operatorCatalog/v1", "mode": "operator-development",
        "productionReady": False, "hardwareVerified": False, "revision": catalog["revision"],
        "policy": observation, "proxy_url": settings["proxy_url"], "allowed_upstreams": settings["allowed_upstreams"],
        **{collection: [_public(collection, row, catalog, observation, now, static_generations) for row in catalog[collection]]
           for collection in _RESULT_KEYS}, "limits": limits, "observed_activity": observed_activity,
        # Source capability, not proof of a deployed gate version. Publication
        # requires the co-versioned request/response/replacement gate (including
        # V2 metadata discard and explicit Basic transport); never downgrade.
        "capabilities": {"credential_types": ["bearer", "header"] + (["google_oauth"] if google_oauth else []),
            "application_proxy_authentication": {"schema": "serverware.operatorProxyAuthentication/v1",
                "modes": ["bearer", "basic_and_bearer_v1"],
                "path": "/api/operator-demo/applications/proxy-authentication"},
            "static_key_replacement": {"schema": "serverware.operatorStaticKeyReplacement/v1",
                "path": "/api/operator-demo/credentials/replace-key", "credential_types": ["bearer", "header"]},
            "aws_credentials": operator_catalog_aws.capability(),
            "response_modes": ["projected_json", "unfiltered_json", "unfiltered_json_or_empty_v1",
                "unfiltered_json_or_empty_v2"], "oauth": google_oauth is not None,
            "google_oauth": google_oauth,
            "google_disconnect": google_disconnect,
            "google_reauthorization": google_reauthorization,
            "github": operator_catalog_github.capability(),
            "github_app": operator_github_app.capability(),
            "x": operator_catalog_x._capability() if x_available else None,
            "alchemy": operator_catalog_alchemy._capability() if alchemy_available else None,
            "npm": operator_catalog_npm.capability(),
            "npm_publish": operator_catalog_npm_publish.capability(),
            "npm_install": operator_catalog_npm_install._capability() if npm_install_available
                and operator_catalog_npm_install.ORIGIN in settings["allowed_upstreams"] else None,
            "operation_bundles": operation_bundles,
            "request_body_modes": ["preserve_json_v1"],
            "credential_input_modes": ["insert", "replace_exact"],
            "token_lifetime_seconds": {"min": MIN_TOKEN_LIFETIME_SECONDS, "max": MAX_TOKEN_LIFETIME_SECONDS,
                "default": DEFAULT_TOKEN_LIFETIME_SECONDS}}}
