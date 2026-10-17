"""Metadata-only catalog joins for explicitly owned ordinary X OAuth accounts.

Neither a syntactically valid record nor an OAuth token grants account ownership.
The consent/refresh owner retains that evidence and owns encrypted token writes.
These joins do not adopt legacy X rows, read tokens or borrow Google's profile.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import json
import re
import time
import uuid

from catchplate import operator_x_oauth_profile as profiles
from catchplate import operator_catalog_schema as schema

AUTH_TYPE = "x_oauth"
CONNECTION = "x_user_oauth_v1"
MARKER = "operator_x_account"
BINDING_SCHEMA = "catchplate.operatorXAccountBinding/v1"
_SUBJECT = re.compile(r"[1-9][0-9]{0,19}\Z")
_ACCOUNT = re.compile(r"@[A-Za-z0-9_]{1,15}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_INT = 9_007_199_254_740_991
_BINDING_FIELDS = frozenset({"schema", "owner_id", "configuration_operation_id",
    "config_version", "profile_binding_digest", "intent_id"})
_METADATA_FIELDS = frozenset({"oauth", "provider", "provider_id", "oauth_client_id", "x_app_id",
    "provider_subject", "provider_account", "provider_identity_verified", "scopes", "refreshable",
    "injection_field", "expires_at_epoch_ms", MARKER})
_RECORD_FIELDS = frozenset({"id", "ordinal", "version", "name", "created_at", "status",
    "revoked_at", "auth_type", "header_name", "connection_type", "provider_subject",
    "provider_account", "oauth_client_id", "scopes", "permission_preset", MARKER,
    "quarantine_work_id", "quarantined_at", "quarantine_reason"})


def _require(condition):
    if not condition:
        raise schema.CatalogIntegrityError("operator X account binding refused")


def _uuid(value):
    try:
        return type(value) is str and len(value) == 36 and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _timestamp(value):
    try:
        return (type(value) is str and value.isascii() and 1 <= len(value) <= 64
            and all(32 <= ord(char) <= 126 for char in value)
            and datetime.fromisoformat(value).tzinfo is not None)
    except ValueError:
        return False


def selected(record: dict) -> bool:
    # Contradictory markers are selected for refusal, never generic fallback.
    return (record.get("auth_type") == AUTH_TYPE or record.get("connection_type") == CONNECTION
        or MARKER in record)


def _binding(value, profile=None):
    _require(type(value) is dict and set(value) == _BINDING_FIELDS
        and value["schema"] == BINDING_SCHEMA
        and all(_uuid(value[key]) for key in ("owner_id", "configuration_operation_id", "intent_id"))
        and type(value["config_version"]) is int and value["config_version"] == 1
        and type(value["profile_binding_digest"]) is str and _SHA.fullmatch(value["profile_binding_digest"]))
    if profile is not None:
        try:
            profiles.validate_profile(profile)
        except (TypeError, ValueError):
            _require(False)
        _require(value["profile_binding_digest"] == profile.binding_digest)


def _identity(subject, account, client, scopes):
    _require(type(subject) is str and _SUBJECT.fullmatch(subject)
        and type(account) is str and _ACCOUNT.fullmatch(account)
        and type(scopes) is list and scopes == list(profiles.SCOPES)
        and all(type(item) is str for item in scopes))
    try:
        profiles.validate_client_id(client)
    except (TypeError, ValueError):
        _require(False)


def validate_account_metadata(metadata: dict, profile=None) -> dict:
    """Close public token metadata; no token parsing, decryption or renewal."""
    _require(type(metadata) is dict and _METADATA_FIELDS <= set(metadata)
        and set(metadata) <= _METADATA_FIELDS | {"refresh_token_expires_at_epoch_ms"})
    _require(metadata["oauth"] is True and metadata["refreshable"] is True
        and metadata["provider_identity_verified"] is True
        and metadata["provider_id"] == "x" and metadata["provider"] == "x.oauth2"
        and metadata["injection_field"] == "access_token"
        and metadata["x_app_id"] == metadata["oauth_client_id"])
    _identity(metadata["provider_subject"], metadata["provider_account"],
        metadata["oauth_client_id"], metadata["scopes"])
    _binding(metadata[MARKER], profile)
    for name in ("expires_at_epoch_ms", "refresh_token_expires_at_epoch_ms"):
        if name in metadata:
            _require(type(metadata[name]) is int and 1 <= metadata[name] <= _MAX_INT)
    if profile is not None:
        _require(metadata["oauth_client_id"] == profile.client_id)
    return deepcopy(metadata)


def validate_identity(record: dict, profile=None) -> None:
    """Validate retained public shape even when the local account is disabled."""
    _require(type(record) is dict and not set(record) - _RECORD_FIELDS
        and record.get("auth_type") == AUTH_TYPE and record.get("connection_type") == CONNECTION
        and record.get("header_name") == "Authorization"
        and record.get("permission_preset") == profiles.PERMISSION_PRESET)
    _identity(record.get("provider_subject"), record.get("provider_account"),
        record.get("oauth_client_id"), record.get("scopes"))
    _binding(record.get(MARKER), profile)
    if profile is not None:
        _require(record["oauth_client_id"] == profile.client_id)


def _metadata(core):
    value = core.get("metadata")
    if type(value) is str:
        def pairs(items):
            result = {}
            for key, item in items:
                _require(key not in result)
                result[key] = item
            return result
        try:
            value = json.loads(value, object_pairs_hook=pairs)
        except (ValueError, RecursionError):
            _require(False)
    return value


def record_fields(core_credential, profile) -> dict:
    """Projection for the consent owner's existing atomic adoption transaction."""
    core = dict(core_credential)
    metadata = validate_account_metadata(_metadata(core), profile)
    _require(core.get("kind") == "oauth2" and core.get("lifecycle_status") == "active"
        and _uuid(core.get("id")) and type(core.get("name")) is str
        and _timestamp(core.get("created_at")))
    record = {"id": core["id"], "name": core["name"], "created_at": core["created_at"],
        "status": "active", "auth_type": AUTH_TYPE, "header_name": "Authorization",
        "connection_type": CONNECTION, "permission_preset": profiles.PERMISSION_PRESET,
        **{key: deepcopy(metadata[key]) for key in
            ("provider_subject", "provider_account", "oauth_client_id", "scopes", MARKER)}}
    validate_record(record, core, profile)
    return record


def _validate_record(record, core_credential, profile):
    core = dict(core_credential) if core_credential is not None else {}
    validate_identity(record, profile)
    metadata = validate_account_metadata(_metadata(core), profile)
    _require(core.get("id") == record.get("id") and core.get("kind") == "oauth2"
        and ("name" not in core or core["name"] == record.get("name"))
        and all(record[key] == metadata[key] for key in
            ("provider_subject", "provider_account", "oauth_client_id", "scopes", MARKER)))
    return metadata


def validate_record(record, core_credential, profile=None) -> dict:
    core = dict(core_credential) if core_credential is not None else {}
    _require(record.get("status") == core.get("lifecycle_status") == "active")
    return _validate_record(record, core, profile)


def validate_quarantined_record(record, core_credential, profile=None) -> dict:
    core = dict(core_credential) if core_credential is not None else {}
    _require(record.get("status") == "quarantined" and core.get("lifecycle_status") == "revocation_pending"
        and _uuid(record.get("quarantine_work_id"))
        and _timestamp(record.get("quarantined_at"))
        and record.get("quarantine_reason") == "operator_x_cleanup_fence")
    return _validate_record(record, core, profile)


def validate_configuration_binding(record, configuration) -> None:
    """Bind to the caller's actual retained configuration, not a supplied digest."""
    _require(type(configuration) is dict and {"public_profile", "owner_id", "operation_id",
        "config_version", "profile_binding_digest"} <= set(configuration))
    _require(_uuid(configuration["owner_id"]) and _uuid(configuration["operation_id"])
        and type(configuration["config_version"]) is int and configuration["config_version"] == 1
        and type(configuration["profile_binding_digest"]) is str
        and _SHA.fullmatch(configuration["profile_binding_digest"]))
    try:
        profile = profiles.parse_profile(configuration["public_profile"])
    except (KeyError, TypeError, ValueError):
        _require(False)
    validate_identity(record, profile)
    binding = record[MARKER]
    _require(binding["owner_id"] == configuration["owner_id"]
        and binding["configuration_operation_id"] == configuration["operation_id"]
        and binding["config_version"] == configuration["config_version"]
        and binding["profile_binding_digest"] == configuration["profile_binding_digest"])


def require_lease_binding(conn, *, principal_id: str, route_id: str,
        credential_id: str, core_credential: dict, profile=None) -> dict:
    """Read-only exact account/configuration/rule join under caller custody.

    This never obtains tokens, refreshes, observes HTTP or initializes state.
    The caller still owns current generation and original request deadlines.
    """
    from catchplate import operator_x_configuration, operator_catalog_x_post
    configuration = operator_x_configuration.retained_public_binding(conn)
    _require(configuration is not None)
    actual_profile = profiles.parse_profile(configuration["public_profile"])
    if profile is not None:
        _require(profile == actual_profile)
    catalog = schema.read_catalog(conn)
    credentials = [row for row in catalog["credentials"] if row["id"] == credential_id]
    rules = [row for row in catalog["access_rules"] if row.get("route_id") == route_id]
    applications = [row for row in catalog["applications"] if row.get("principal_id") == principal_id]
    _require(len(credentials) == len(rules) == len(applications) == 1)
    credential, rule, application = credentials[0], rules[0], applications[0]
    _require(rule.get("status") == application.get("status") == "active"
        and rule.get("credential_id") == credential_id and rule.get("application_id") == application["id"]
        and type(application.get("token_expires_at_epoch_ms")) is int
        and application["token_expires_at_epoch_ms"] > time.time_ns() // 1_000_000)
    validate_configuration_binding(credential, configuration)
    validate_record(credential, core_credential, actual_profile)
    operator_catalog_x_post.validate_rule(rule, credential)
    return credential


def credential_policy(record: dict) -> dict:
    validate_identity(record)
    return {"id": record["id"], "credentialType": "oauth2", "provider": "x",
        "providerSubject": record["provider_subject"], "oauthClientId": record["oauth_client_id"],
        "scopes": list(record["scopes"]),
        "injection": {"type": "bearer", "header": "Authorization", "field": "access_token"}}


def route_binding(record: dict) -> dict:
    validate_identity(record)
    return {"credentialType": "oauth2", "provider": "x", "subjects": [record["provider_subject"]],
        "clientIds": [record["oauth_client_id"]], "requiredScopes": list(record["scopes"])}


def public_fields(record: dict) -> dict:
    validate_identity(record)
    result = {"connection_type": CONNECTION, "provider_id": "x", **{key: deepcopy(record[key])
        for key in ("provider_account", "provider_subject", "oauth_client_id", "scopes", "permission_preset")}}
    if record.get("status") == "quarantined":
        result.update(quarantined_at=record["quarantined_at"],
            quarantine_reason=record["quarantine_reason"], provider_revocation_status="not_proven")
    return result


def capability() -> dict:
    """Only expose after the caller's same-health configured-pair join."""
    return {"schema": "catchplate.operatorXOAuth/v1", "connection_type": CONNECTION,
        "auth_type": AUTH_TYPE, "permission_preset": profiles.PERMISSION_PRESET,
        "start_path": "/api/operator-demo/oauth/x/start",
        "operation_path_prefix": "/api/operator-demo/oauth/x/operations/",
        "disconnect_review_path_template": "/api/operator-demo/oauth/x/accounts/{credential_id}/disconnect-review",
        "disconnect_path": "/api/operator-demo/oauth/x/disconnect", "source_pair_required": True,
        "automatic_refresh": True, "daily_quota_available": False}
