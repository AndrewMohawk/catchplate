"""Explicit GitHub token/preset metadata; no discovery or provider contact.

Existing bearer credentials and rules are never inferred to be GitHub resources.
Repository names are reviewed authority, not a claim about provider permissions.
The co-versioned request processor normalizes pagination onto this named scope;
numeric repository paths are never additional signed client authority.
"""
from __future__ import annotations

from copy import deepcopy
import re

from serverware.operator_catalog_schema import CatalogIntegrityError

CONNECTION = "github_token_v1"
READ_BUNDLE = "github_issues_read_v1"
WRITE_BUNDLE = "github_issues_write_v1"
BUNDLES = (READ_BUNDLE, WRITE_BUNDLE)
ORIGIN = "https://api.github.com"
QUERY_MODE = "githubRestV1"
RESPONSE_MODE = "unfiltered_json_or_empty_v2"
SDK_TOKEN = "serverware-github-placeholder-v1"
PLACEHOLDER = "token " + SDK_TOKEN


def validate_token(value: str) -> str:
    """Accept opaque GitHub tokens, not PEM keys or App JWT credentials."""
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_]{1,8192}", value) is None:
        raise ValueError("invalid GitHub token format")
    return value


def selected(rule: dict) -> bool:
    return rule.get("operation_bundle") in BUNDLES


def validate_credential(record: dict, metadata: dict | None = None) -> bool:
    from serverware import operator_github_app as app_connection
    from serverware import github_app_boundary
    if (github_app_boundary.selected(record.get("auth_type"), record)
            or github_app_boundary.selected(None, metadata)):
        return app_connection.validate_credential(record, metadata)
    marker = record.get("connection_type")
    if "connection_type" not in record:
        if metadata is not None and "connection_type" in metadata:
            raise CatalogIntegrityError("catalog credential connection binding refused")
        return False
    if (marker != CONNECTION or record.get("auth_type") != "bearer"
            or record.get("header_name") != "Authorization"
            or metadata is not None and metadata.get("connection_type") != CONNECTION):
        raise CatalogIntegrityError("catalog GitHub token binding refused")
    return True


def _derived_fields(bundle: str, repository: dict) -> dict:
    from serverware import github_issues
    github_issues.validate_repository(repository)
    request = github_issues.request_profile(bundle)
    return {"upstream_url": ORIGIN + "/repos/" + repository["owner"] + "/" + repository["name"] + "/issues",
        "methods": ["GET"] if bundle == READ_BUNDLE else ["GET", "POST"],
        "request_fields": [], "response_fields": [], "request_body_mode": "preserve_json_v1",
        "query_keys": list(request["allowedQueryKeys"]), "allowed_headers": list(request["allowedHeaders"]),
        "response_mode": RESPONSE_MODE, "credential_input": "replace_exact",
        "placeholder": PLACEHOLDER, "query_mode": QUERY_MODE}


def record_fields(payload) -> dict:
    record = payload.model_dump(exclude={"expected_revision", "expected_policy_hash"})
    record.update(_derived_fields(record["operation_bundle"], record["repository"]))
    validate_shape(record)
    return record


def validate_shape(rule: dict) -> None:
    if not selected(rule) or "age_policy" in rule:
        raise CatalogIntegrityError("operator GitHub bundle contract refused")
    try:
        expected = _derived_fields(rule["operation_bundle"], rule["repository"])
    except (KeyError, TypeError, ValueError) as error:
        raise CatalogIntegrityError("operator GitHub repository contract refused") from error
    if any(rule.get(key) != value for key, value in expected.items()):
        raise CatalogIntegrityError("operator GitHub derived profile refused")


def validate_rule(rule: dict, credential: dict) -> None:
    validate_shape(rule)
    if not validate_credential(credential):
        raise CatalogIntegrityError("GitHub preset requires a GitHub token connection")
    from serverware import operator_github_app as app_connection
    if credential.get("connection_type") == app_connection.CONNECTION:
        binding = credential["github_app"]
        if (rule["repository"] != binding["repository"] or
                binding["issues_permission"] == "read" and rule["operation_bundle"] != READ_BUNDLE):
            raise CatalogIntegrityError("GitHub App repository or permission ceiling refused")


def render_route(rule: dict, credential: dict, principal_id: str) -> dict:
    from serverware import github_issues
    validate_rule(rule, credential)
    return {"id": rule["route_id"], "principals": [principal_id],
        "match": {"scheme": "https", "host": "api.github.com", "port": 443,
            "methods": list(rule["methods"]), "paths": list(github_issues.route_paths(rule["repository"]))},
        "credentialRef": credential["id"], "adapter": {"type": "generic.rest", "config": {
            "credentialMode": "required",
            "credentialBinding": {"credentialType": "static", "provider": "operator-demo",
                "subjects": [credential["provider_subject"]], "secretClass": "bearerToken"},
            "githubRepository": deepcopy(rule["repository"]), "operationBundle": rule["operation_bundle"],
            "request": github_issues.request_profile(rule["operation_bundle"]),
            "response": github_issues.response_profile()}},
        "constraints": [github_issues.response_envelope(rule["route_id"] + ".envelope")]}


def public_fields(rule: dict) -> dict:
    validate_shape(rule)
    return {"operation_bundle": rule["operation_bundle"], "repository": deepcopy(rule["repository"]),
        "query_mode": QUERY_MODE}


def capability() -> dict:
    from serverware import operator_demo
    return {"schema": "serverware.operatorGithub/v1", "connection_type": CONNECTION,
        "create_credential_path": "/api/operator-demo/credentials/github-token",
        "create_rule_path": "/api/operator-demo/access-rules/github", "api_origin": ORIGIN,
        "destination_allowed": ORIGIN in operator_demo.settings()["allowed_upstreams"],
        "operation_bundles": list(BUNDLES), "sdk_auth_token": SDK_TOKEN, "placeholder": PLACEHOLDER,
        "query_mode": QUERY_MODE, "response_mode": RESPONSE_MODE, "source_pair_required": True}
