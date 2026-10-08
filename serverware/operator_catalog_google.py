"""Metadata-only joins for explicitly admitted operator Google accounts.

Consent and provider cleanup belong to the existing OAuth lifecycle. These
helpers neither open token ciphertext nor acquire publication ownership. Lease
validation is read-only inside its caller's actual credential-generation lock.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from urllib.parse import urlsplit

from serverware import operator_catalog_schema as schema

AUTH_TYPE = "google_oauth"
_TABLE = "operator_catalog_oauth_profile"
_GMAIL_PATH = re.compile(
    r"/gmail/v1/users/me/(?:profile|history|(?:messages|threads|labels)(?:/[A-Za-z0-9_-]+)?)\Z"
)


def _require(condition: bool) -> None:
    if not condition:
        raise schema.CatalogIntegrityError("operator Google account binding refused")


def _uuid(value) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _text(value, maximum=256) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum and not any(
        ord(char) < 32 or ord(char) == 127 for char in value
    )


def initialize_profile(conn) -> None:
    """Pin public configuration once; never silently adopt changed OAuth apps."""
    from serverware import operator_catalog_oauth_profile as profiles
    schema._transaction(conn)
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (_TABLE,)
    ).fetchone()
    if not profiles.selected():
        _require(exists is None)
        return
    profile = profiles.require_profile()
    expected = json.dumps(profiles.binding_record(), sort_keys=True,
        separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if exists is None:
        conn.execute("CREATE TABLE " + _TABLE + " (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
            "binding_json TEXT NOT NULL,binding_digest TEXT NOT NULL)")
        conn.execute("INSERT INTO " + _TABLE + " VALUES (1,?,?)", (expected, profile.binding_digest))
    validate_profile_binding(conn)
    from serverware import operator_catalog_oauth
    operator_catalog_oauth.initialize(conn)


def validate_profile_binding(conn):
    """Recheck retained configuration without DDL or acquiring a write lock."""
    from serverware import operator_catalog_oauth_profile as profiles
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (_TABLE,)
    ).fetchone()
    if not profiles.selected():
        _require(exists is None)
        return None
    profile = profiles.require_profile()
    _require(exists is not None)
    expected = json.dumps(profiles.binding_record(), sort_keys=True,
        separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    rows = conn.execute("SELECT singleton,binding_json,binding_digest FROM " + _TABLE).fetchall()
    _require(len(rows) == 1 and rows[0]["singleton"] == 1
        and rows[0]["binding_json"] == expected and rows[0]["binding_digest"] == profile.binding_digest)
    return profile


def validate_record(record: dict, core_credential: dict, profile=None) -> dict:
    """Join immutable catalog identity to the real active encrypted-store row."""
    from serverware import operator_catalog_oauth_profile as profiles
    profile = profiles.require_profile() if profile is None else profile
    core = dict(core_credential) if core_credential is not None else {}
    metadata = core.get("metadata")
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except (ValueError, TypeError):
            metadata = None
    _require(isinstance(metadata, dict))
    _require(record.get("auth_type") == AUTH_TYPE and record.get("header_name") == "Authorization"
        and record.get("status") == "active" and core.get("id") == record.get("id")
        and core.get("kind") == "oauth2" and core.get("lifecycle_status") == "active")
    if "name" in core:
        _require(core["name"] == record.get("name"))
    _require(metadata.get("oauth") is True and metadata.get("refreshable") is True
        and metadata.get("provider_id") == "google" and metadata.get("provider") == "google.oauth2"
        and metadata.get("provider_identity_verified") is True
        and metadata.get("injection_field") == "access_token")
    _require(record.get("oauth_client_id") == metadata.get("oauth_client_id") == profile.client_id
        and record.get("permission_preset") == profile.permission_preset
        and record.get("oauth_profile_binding_digest")
            == metadata.get("oauth_profile_binding_digest") == profile.binding_digest)
    _require(_text(record.get("provider_subject"))
        and record["provider_subject"] == metadata.get("provider_subject")
        and _text(record.get("provider_account"))
        and record["provider_account"] == metadata.get("provider_account")
        and _uuid(record.get("oauth_intent_id"))
        and record["oauth_intent_id"] == metadata.get("oauth_intent_id"))
    scopes, actual = record.get("scopes"), metadata.get("scopes")
    _require(isinstance(scopes, list) and all(isinstance(value, str) for value in scopes)
        and scopes == sorted(set(scopes)) == list(profile.scopes)
        and isinstance(actual, list) and all(isinstance(value, str) for value in actual)
        and len(actual) == len(set(actual)) and sorted(actual) == scopes)
    return metadata


def validate_rule(rule: dict, credential: dict, profile=None) -> None:
    """Initial exact Gmail reads; not a complete Gmail operation preset."""
    from serverware import operator_catalog_oauth_profile as profiles
    profile = profiles.require_profile() if profile is None else profile
    parsed = urlsplit(rule.get("upstream_url", ""))
    _require(credential.get("auth_type") == AUTH_TYPE
        and credential.get("oauth_profile_binding_digest") == profile.binding_digest
        and parsed.scheme == "https" and parsed.netloc == "gmail.googleapis.com"
        and "https://gmail.googleapis.com" in profile.api_origins
        and not parsed.query and not parsed.fragment and _GMAIL_PATH.fullmatch(parsed.path) is not None
        and rule.get("methods") == ["GET"] and rule.get("request_fields") == [])


def credential_policy(record: dict) -> dict:
    return {"id": record["id"], "credentialType": "oauth2", "provider": "google",
        "providerSubject": record["provider_subject"], "oauthClientId": record["oauth_client_id"],
        "scopes": list(record["scopes"]),
        "injection": {"type": "bearer", "header": "Authorization", "field": "access_token"}}


def route_binding(record: dict) -> dict:
    return {"credentialType": "oauth2", "provider": "google",
        "subjects": [record["provider_subject"]], "clientIds": [record["oauth_client_id"]],
        "requiredScopes": list(record["scopes"])}


def require_lease_binding(conn, *, principal_id: str, route_id: str,
        credential_id: str, core_credential: dict, profile) -> dict:
    """Read only: caller holds the real SQLite generation mutation snapshot."""
    _require(validate_profile_binding(conn) == profile)
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
    validate_record(credential, core_credential, profile)
    validate_rule(rule, credential, profile)
    return credential


def public_fields(record: dict) -> dict:
    """No tokens or guessed refresh-health states in the management response."""
    return {key: record[key] for key in (
        "provider_account", "provider_subject", "oauth_client_id", "scopes", "permission_preset"
    )}
