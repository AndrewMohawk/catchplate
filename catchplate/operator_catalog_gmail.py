"""Explicit Gmail message-read bundle; no legacy rule conversion or provider I/O.

One catalog permission owns one signed route with two typed operations. Age
restriction is explicit and requires fresh internalDate evidence at the Rust
gate; it is never an implicit migration or a query-only substitute.
"""
from __future__ import annotations

from copy import deepcopy

from catchplate.operator_catalog_schema import CatalogIntegrityError

BUNDLE = "gmail_read_v1"
ADAPTER = "gmail.read.v1"
RESPONSE_MODE = "gmail_read_json_v1"
ORIGIN = "https://gmail.googleapis.com"
LIST_PATH = "/gmail/v1/users/me/messages"
PATHS = (LIST_PATH, LIST_PATH + "/{message_id}")
READ_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
QUERY_MODE = "orderedFormV1"


def selected(rule: dict) -> bool:
    """Absence preserves the exact legacy contract; unknown versions refuse."""
    if "operation_bundle" not in rule:
        if "query_mode" in rule:
            raise CatalogIntegrityError("operator query mode requires a typed bundle")
        return False
    if rule["operation_bundle"] != BUNDLE:
        raise CatalogIntegrityError("operator operation bundle unavailable")
    return True


def _query_mode(rule: dict) -> str | None:
    if "query_mode" not in rule:
        return None  # Retained pre-query bundles are never silently upgraded.
    if rule["query_mode"] != QUERY_MODE:
        raise CatalogIntegrityError("operator Gmail query mode refused")
    return QUERY_MODE


def _derived_fields(query_mode: str | None = None) -> dict:
    from catchplate.policy_bundle import provider_request_profile
    request = provider_request_profile(ADAPTER, query_mode=query_mode)
    return {"upstream_url": ORIGIN + LIST_PATH, "methods": ["GET"],
        "request_fields": [], "response_fields": [],
        "query_keys": list(request["allowedQueryKeys"]),
        "allowed_headers": list(request["allowedHeaders"]), "response_mode": RESPONSE_MODE}


def record_fields(payload) -> dict:
    value = payload.model_dump(exclude={"expected_revision", "expected_policy_hash"})
    if payload.credential_input == "insert":
        value.pop("placeholder", None)
    value.update(_derived_fields(QUERY_MODE))
    value["query_mode"] = QUERY_MODE
    validate_shape(value)
    return value


def _signed_age_policy(rule: dict) -> dict:
    value = rule.get("age_policy")
    if value == {"mode": "unrestricted"}:
        return {"mode": "unrestricted"}
    if (not isinstance(value, dict) or set(value) != {"mode", "max_age_days"}
            or value["mode"] != "recent_internal_date_v1"
            or type(value["max_age_days"]) is not int or not 1 <= value["max_age_days"] <= 3650
            or _query_mode(rule) != QUERY_MODE):
        raise CatalogIntegrityError("operator Gmail age policy refused")
    return {"mode": "recent_internal_date_v1", "maxAgeDays": value["max_age_days"]}


def validate_shape(rule: dict) -> None:
    query_mode = _query_mode(rule)
    _signed_age_policy(rule)
    if (not selected(rule)
            or "request_body_mode" in rule
            or any(rule.get(key) != value for key, value in _derived_fields(query_mode).items())):
        raise CatalogIntegrityError("operator Gmail bundle contract refused")


def validate_rule(rule: dict, credential: dict, profile) -> None:
    validate_shape(rule)
    if (credential.get("auth_type") != "google_oauth"
            or credential.get("header_name") != "Authorization"
            or credential.get("oauth_profile_binding_digest") != profile.binding_digest
            or credential.get("oauth_client_id") != profile.client_id
            or credential.get("scopes") != list(profile.scopes)
            or READ_SCOPE not in profile.scopes or ORIGIN not in profile.api_origins):
        raise CatalogIntegrityError("operator Gmail account binding refused")


def render_route(rule: dict, credential: dict, principal_id: str) -> dict:
    from catchplate.policy_bundle import (
        gmail_read_response_envelope, gmail_read_response_profile, provider_request_profile,
    )
    validate_shape(rule)
    return {"id": rule["route_id"], "principals": [principal_id],
        "match": {"scheme": "https", "host": "gmail.googleapis.com", "port": 443,
            "methods": ["GET"], "paths": list(PATHS)},
        "credentialRef": credential["id"], "adapter": {"type": ADAPTER, "config": {
            "credentialBinding": {"credentialType": "oauth2", "provider": "google",
                "subjects": [credential["provider_subject"]],
                "clientIds": [credential["oauth_client_id"]], "requiredScopes": [READ_SCOPE]},
            "request": provider_request_profile(ADAPTER, query_mode=_query_mode(rule)),
            "agePolicy": _signed_age_policy(rule),
            "response": gmail_read_response_profile()}},
        "constraints": [gmail_read_response_envelope(rule["route_id"] + ".envelope")]}


def public_fields(rule: dict) -> dict:
    validate_shape(rule)
    result = {"operation_bundle": BUNDLE, "age_policy": deepcopy(rule["age_policy"])}
    if "query_mode" in rule:
        result["query_mode"] = _query_mode(rule)
    return result


def capabilities(conn) -> list[dict]:
    """Source-pair discovery, not deployed-gate attestation or provider health.

    The caller holds a catalog read snapshot. Cold admission excludes native
    and enrolled profiles, and the retained profile must match in that snapshot.
    Deployments must pair this source with its matching gate before publishing.
    """
    from catchplate import operator_catalog_google
    from catchplate.policy_bundle import (
        gmail_read_response_envelope, gmail_read_response_profile, provider_request_profile,
    )
    if getattr(conn, "in_transaction", False) is not True:
        raise CatalogIntegrityError("operator capability requires a catalog read snapshot")
    profile = operator_catalog_google.validate_profile_binding(conn)
    if profile is None:
        return []
    request = provider_request_profile(ADAPTER, query_mode=QUERY_MODE)
    response = gmail_read_response_profile()
    envelope = gmail_read_response_envelope("capability")
    if (request.get("queryMode") != QUERY_MODE or profile.permission_preset != "gmail_readonly"
            or ORIGIN not in profile.api_origins or READ_SCOPE not in profile.scopes):
        raise CatalogIntegrityError("operator Gmail capability unavailable")
    return [{"operation_bundle": BUNDLE,
        "create_path": "/api/operator-demo/access-rules/gmail-read",
        "credential_type": "google_oauth", "permission_preset": profile.permission_preset,
        "api_origin": ORIGIN, "methods": ["GET"], "paths": list(PATHS),
        "query_mode": QUERY_MODE, "age_policy": {"mode": "unrestricted"},
        "age_policy_options": [{"mode": "unrestricted"},
            {"mode": "recent_internal_date_v1", "min_age_days": 1,
                "max_age_days": 3650, "max_list_results": 32}],
        "response_mode": RESPONSE_MODE, "response_contract": {
            "mode": response["mode"], "body_presence": envelope["bodyPresence"],
            "content_types": list(response["contentTypes"]), "success_status_codes": [200],
            "error_status_codes": [value for value in envelope["statusCodes"] if value != 200],
            "max_body_bytes": response["maxBodyBytes"],
            "max_error_body_bytes": response["error"]["maxBodyBytes"],
            "unlisted_header_policy": envelope["unlistedHeaderPolicy"]}}]
