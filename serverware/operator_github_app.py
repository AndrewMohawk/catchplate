"""Ordinary operator GitHub App custody and bounded installation-token renewal.

Only the existing encrypted credential row retains the private configuration.
Tokens live in bounded process memory; minting is authentication provisioning,
not a repository mutation. A failed attempt is not retried in the same call.
A later authorized lease may mint after a 60-second backoff; restart loses this
memory, not durable authority. No token revocation or crash recovery is claimed.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
import re
import threading
import time
import uuid

from serverware import github_app as protocol, github_app_boundary as boundary

CONNECTION = boundary.CONNECTION
SECRET_SCHEMA = boundary.SECRET_SCHEMA
_PUBLIC = {"app_id", "installation_id", "account_id", "repository_id", "repository",
    "issues_permission", "token_refresh"}
_METADATA = {"provider_id", "provider_subject", "secret_class", "connection_type", "github_app"}
_RECORD = {"id", "ordinal", "version", "name", "created_at", "status", "revoked_at",
    "auth_type", "header_name", "connection_type", "provider_subject", "github_app"}
_CAPACITY = 256
_MARGIN = 65
_BACKOFF = 60.0
_lock = threading.Lock()
_cache = {}
_failures = {}
_inflight = set()
_pid = os.getpid()


def _after_fork():
    global _lock, _pid
    _lock = threading.Lock()
    _cache.clear()
    _failures.clear()
    _inflight.clear()
    _pid = os.getpid()


os.register_at_fork(after_in_child=_after_fork)


class GitHubAppUnavailable(RuntimeError):
    """Fixed public failure; never carries provider bodies, JWTs or key material."""


def _require(condition):
    if not condition:
        raise GitHubAppUnavailable("GitHub App connection unavailable")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def identifier(value):
    if (type(value) is not str or re.fullmatch(r"[1-9][0-9]{0,15}", value) is None
            or int(value) > 9_007_199_254_740_991):
        raise ValueError("GitHub App identifier refused")
    return int(value)


def selected(credential):
    return boundary.credential_selected(credential)


def require_runtime():
    from serverware import config, operator_demo, oauth_application_owner
    _require(operator_demo.active() and config.RELEASE_CHANNEL == "dev"
        and config.PRODUCTION_IMAGE is False and config.METADATA_STORE_BACKEND == "sqlite"
        and config.AUDIT_STORE_BACKEND == "sqlite" and config.GRANT_STORE_BACKEND == "sqlite"
        and config.ATOMIC_RELEASE_AUTHORIZATION_ENABLED is False and config.KEY_RELEASE_REQUIRED is False
        and config.TEE_PLATFORM == "none-dev" and config.TEE_QUOTE_PROVIDER == "dev-signed-quote"
        and oauth_application_owner.require_started() is None)


def public_config(value):
    try:
        _require(type(value) is dict and set(value) == _PUBLIC
            and value["token_refresh"] == "automatic" and type(value["repository"]) is dict
            and set(value["repository"]) == {"owner", "name"})
        return protocol.AppConfig(identifier(value["app_id"]), identifier(value["installation_id"]),
            value["repository"]["owner"], value["repository"]["name"], value["issues_permission"],
            identifier(value["account_id"]), identifier(value["repository_id"]))
    except Exception:
        raise GitHubAppUnavailable("GitHub App connection binding refused") from None


def _public(config):
    value = {"app_id": str(config.app_id), "installation_id": str(config.installation_id),
        "account_id": str(config.account_id), "repository_id": str(config.repository_id),
        "repository": {"owner": config.owner, "name": config.repository},
        "issues_permission": config.issues, "token_refresh": "automatic"}
    public_config(value)
    return value


def validate_metadata(metadata):
    try:
        _require(type(metadata) is dict and set(metadata) == _METADATA
            and metadata["provider_id"] == "operator-demo" and metadata["secret_class"] == "bearerToken"
            and metadata["connection_type"] == CONNECTION
            and type(metadata["provider_subject"]) is str
            and str(uuid.UUID(metadata["provider_subject"])) == metadata["provider_subject"])
        return public_config(metadata["github_app"])
    except Exception:
        raise GitHubAppUnavailable("GitHub App connection binding refused") from None


def validate_credential(record, metadata=None):
    try:
        _require(type(record) is dict and not set(record) - _RECORD
            and record.get("auth_type") == "bearer" and record.get("header_name") == "Authorization"
            and record.get("connection_type") == CONNECTION
            and type(record.get("provider_subject")) is str
            and str(uuid.UUID(record["provider_subject"])) == record["provider_subject"])
        public_config(record["github_app"])
        if metadata is not None:
            validate_metadata(metadata)
            _require(metadata["github_app"] == record["github_app"]
                and metadata["provider_subject"] == record["provider_subject"])
    except Exception:
        from serverware.operator_catalog_schema import CatalogIntegrityError
        raise CatalogIntegrityError("catalog GitHub App binding refused") from None
    return True


def validate_stored(secret, metadata):
    try:
        config = validate_metadata(metadata)
        _require(type(secret) is str and 1 <= len(secret.encode("utf-8")) <= 24576)
        value = json.loads(secret)
        _require(type(value) is dict and set(value) == {"schema", "github_app", "private_key_pem"}
            and value["schema"] == SECRET_SCHEMA and _canonical(value) == secret
            and value["github_app"] == metadata["github_app"]
            and type(value["private_key_pem"]) is str
            and 1 <= len(value["private_key_pem"].encode("utf-8")) <= 8192)
        return config, protocol.load_private_key(value["private_key_pem"].encode("utf-8"))
    except Exception:
        raise GitHubAppUnavailable("GitHub App encrypted configuration refused") from None


@dataclass(frozen=True)
class PreparedConnection:
    public: dict
    secret: str = field(repr=False)
    token: protocol.InstallationToken = field(repr=False)
    observed_wall: float
    observed_monotonic: float


def verify_connection(payload):
    require_runtime()
    from serverware import operator_publication as publication
    publication.assert_not_held()
    try:
        config = protocol.AppConfig(identifier(payload.app_id), identifier(payload.installation_id),
            payload.repository.owner, payload.repository.name, payload.issues_permission)
        key = protocol.load_private_key(payload.private_key_pem.encode("utf-8"))
        token = protocol.mint_installation_token(config, key)
        public = _public(token.config)
        secret = _canonical({"schema": SECRET_SCHEMA, "github_app": public,
            "private_key_pem": payload.private_key_pem})
        return PreparedConnection(public, secret, token, time.time(), time.monotonic())
    except Exception:
        raise GitHubAppUnavailable("GitHub App verification failed; no connection was saved") from None


def metadata(public, subject):
    result = {"provider_id": "operator-demo", "provider_subject": subject,
        "secret_class": "bearerToken", "connection_type": CONNECTION, "github_app": deepcopy(public)}
    validate_metadata(result)
    return result


def _identity(credential):
    _require(type(credential) is dict and credential.get("kind") == "bearer")
    validate_metadata(credential.get("metadata"))
    identifier = credential.get("id")
    _require(type(identifier) is str and str(uuid.UUID(identifier)) == identifier
        and type(credential.get("credential_version")) is int
        and 1 <= credential["credential_version"] <= 9_007_199_254_740_991)
    return identifier, credential["credential_version"], hashlib.sha256(
        _canonical(credential["metadata"]).encode("ascii")).hexdigest()


def validate_route(credential, route, credential_policy):
    from serverware import github_issues, operator_catalog_github as github
    try:
        github_issues.validate_route(route)
        _identity(credential)
        config = validate_metadata(credential["metadata"])
        adapter = route.adapter_config
        bundle = adapter.get("operationBundle")
        repository = {"owner": config.owner, "name": config.repository}
        methods = frozenset({"GET"} if bundle == github.READ_BUNDLE else {"GET", "POST"})
        _require(route.credential_ref == credential["id"] and route.adapter_type == "generic.rest"
            and route.scheme == "https" and route.host == "api.github.com" and route.port == 443
            and bundle in github.BUNDLES and (config.issues == "write" or bundle == github.READ_BUNDLE)
            and route.methods == methods and tuple(route.path_templates) == tuple(github_issues.route_paths(repository))
            and adapter.get("githubRepository") == repository and adapter.get("credentialMode") == "required"
            and adapter.get("credentialBinding") == {"credentialType": "static", "provider": "operator-demo",
                "subjects": [credential["metadata"]["provider_subject"]], "secretClass": "bearerToken"}
            and credential_policy.id == credential["id"] and credential_policy.kind == "static"
            and credential_policy.provider == "operator-demo"
            and credential_policy.provider_subject == credential["metadata"]["provider_subject"]
            and not credential_policy.scopes
            and credential_policy.injection.get("type") == "bearer"
            and credential_policy.injection.get("header") == "Authorization"
            and credential_policy.injection.get("field") is None
            and credential_policy.injection.get("prefix", "Bearer ") == "Bearer ")
    except Exception:
        raise GitHubAppUnavailable("GitHub App repository permission refused") from None


@dataclass(frozen=True)
class _Entry:
    token: protocol.InstallationToken = field(repr=False)
    wall: float
    monotonic: float

    def usable(self):
        if (type(self.token) is not protocol.InstallationToken
                or type(self.wall) not in {int, float} or not math.isfinite(self.wall)
                or type(self.monotonic) not in {int, float} or not math.isfinite(self.monotonic)
                or self.monotonic < 0 or self.wall < self.token.issued_at):
            return False
        now, elapsed = time.time(), time.monotonic() - self.monotonic
        return (elapsed >= 0 and now >= self.wall and self.token.expires_at > now + _MARGIN
            and self.token.expires_at > self.wall + elapsed + _MARGIN)


def _prune():
    global _pid
    if _pid != os.getpid():
        _cache.clear(); _failures.clear(); _inflight.clear(); _pid = os.getpid()
    now = time.monotonic()
    for key in list(_cache):
        if not _cache[key].usable():
            _cache.pop(key)
    for key in list(_failures):
        if _failures[key] <= now:
            _failures.pop(key)


def _put(identity, token, wall, monotonic):
    entry = _Entry(token, wall, monotonic)
    _require(entry.usable())
    with _lock:
        _prune()
        _require(identity in _cache or len(_cache) < _CAPACITY)
        _cache[identity] = entry
        _failures.pop(identity, None)


def seed_committed(credential, prepared):
    """Optional postcommit optimization; caller preserves receipt if this fails."""
    _require(type(prepared) is PreparedConnection
        and credential["metadata"]["github_app"] == prepared.public)
    _put(_identity(credential), prepared.token,
        prepared.observed_wall, prepared.observed_monotonic)


def forget(credential_id):
    with _lock:
        for collection in (_cache, _failures):
            for key in list(collection):
                if key[0] == credential_id:
                    collection.pop(key, None)


def prepare_dispatch_token(credential, route, credential_policy):
    """Exclusive secret reader. Called before the final lease mutation lock."""
    require_runtime()
    from serverware import db, operator_publication as publication
    publication.assert_not_held()
    validate_route(credential, route, credential_policy)
    identity = _identity(credential)
    with _lock:
        _prune()
        if identity in _cache:
            return
        _require(identity not in _failures and identity not in _inflight
            and len(_inflight) < 4 and len(_failures) < _CAPACITY)
        _inflight.add(identity)
        _failures[identity] = time.monotonic() + _BACKOFF
    try:
        current = db.get_credential(credential["id"], include_secret=True)
        _require(current is not None and _identity(current) == identity)
        config, key = validate_stored(current["secret"], current["metadata"])
        token = protocol.mint_installation_token(config, key)
        require_runtime()
        after = db.get_credential(credential["id"], include_secret=False)
        _require(after is not None and _identity(after) == identity and token.config == config)
        _put(identity, token, time.time(), time.monotonic())
    except BaseException:
        with _lock:
            _failures[identity] = time.monotonic() + _BACKOFF
        raise GitHubAppUnavailable("GitHub App token unavailable; refresh is temporarily paused") from None
    finally:
        with _lock:
            _inflight.discard(identity)


def cached_dispatch_token(credential, route, credential_policy):
    """No I/O, decrypt, or mint. Requires the caller's locked current original."""
    validate_route(credential, route, credential_policy)
    identity = _identity(credential)
    with _lock:
        _prune()
        entry = _cache.get(identity)
        _require(entry is not None and entry.usable())
        return entry.token.token


def capability():
    from serverware import operator_catalog_github as github
    value = github.capability()
    return {**value, "schema": "serverware.operatorGithubApp/v1", "connection_type": CONNECTION,
        "create_credential_path": "/api/operator-demo/credentials/github-app"}
