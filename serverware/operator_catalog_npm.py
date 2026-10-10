"""Explicit npm metadata grants; no install, tarball, publish or discovery.

The public npm marker does not verify the provider account or token permissions.
Encrypted custody retains the existing operator-demo static credential binding.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from serverware.operator_catalog_schema import CatalogIntegrityError

CONNECTION = "npm_token_v1"
BUNDLE = "npm_metadata_read_v1"
ORIGIN = "https://registry.npmjs.org"
RESPONSE_MODE = "npm_metadata_json_v1"
SDK_TOKEN = "serverware-npm-placeholder-v1"
PLACEHOLDER = "Bearer " + SDK_TOKEN


def validate_token(value: str) -> str:
    """Bounded opaque bearer syntax, not npm account/permission verification."""
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9._~+/-]+={0,}", value) is None or len(value) > 8192:
        raise ValueError("invalid npm token format")
    return value


def selected(rule: dict) -> bool:
    return rule.get("operation_bundle") == BUNDLE


def validate_credential(record: dict, metadata: dict | None = None) -> bool:
    if (record.get("connection_type") != CONNECTION or record.get("auth_type") != "bearer"
            or record.get("header_name") != "Authorization"
            or metadata is not None and metadata.get("connection_type") != CONNECTION):
        raise CatalogIntegrityError("catalog npm token binding refused")
    return True


def _derived_fields(packages: list[str]) -> dict:
    from serverware import npm_metadata
    npm_metadata.validate_packages(packages)
    request = npm_metadata.request_profile()
    return {"upstream_url": ORIGIN + "/", "methods": ["GET"],
        "request_fields": [], "response_fields": [], "query_keys": [],
        "allowed_headers": list(request["allowedHeaders"]), "response_mode": RESPONSE_MODE,
        "credential_input": "replace_exact", "placeholder": PLACEHOLDER}


def record_fields(payload) -> dict:
    record = payload.model_dump(exclude={"expected_revision", "expected_policy_hash"})
    record.update(_derived_fields(record["packages"]))
    validate_shape(record)
    return record


def validate_shape(rule: dict) -> None:
    if not selected(rule) or any(key in rule for key in ("repository", "age_policy", "query_mode", "request_body_mode")):
        raise CatalogIntegrityError("operator npm metadata contract refused")
    try:
        expected = _derived_fields(rule["packages"])
    except (KeyError, TypeError, ValueError) as error:
        raise CatalogIntegrityError("operator npm package contract refused") from error
    if any(rule.get(key) != value for key, value in expected.items()):
        raise CatalogIntegrityError("operator npm derived profile refused")


def validate_rule(rule: dict, credential: dict) -> None:
    validate_shape(rule)
    validate_credential(credential)


def validate_route_coexistence(rules: list[dict]) -> None:
    """Only npm's new universal single-segment route needs this overlap guard."""
    active = [rule for rule in rules if rule.get("status") == "active"]
    applications = set()
    for rule in active:
        if not selected(rule):
            continue
        application = rule["application_id"]
        if application in applications:
            raise CatalogIntegrityError("only one active npm metadata rule is supported per application")
        applications.add(application)
    for rule in active:
        if selected(rule) or rule["application_id"] not in applications or "GET" not in rule.get("methods", []):
            continue
        try:
            target = urlsplit(rule["upstream_url"])
            overlap = (target.scheme == "https" and target.hostname == "registry.npmjs.org"
                and target.port in {None, 443} and re.fullmatch(r"/[^/]+", target.path) is not None)
        except (KeyError, TypeError, ValueError) as error:
            raise CatalogIntegrityError("operator npm route coexistence refused") from error
        if overlap:
            raise CatalogIntegrityError("npm metadata rule conflicts with a registry GET rule for this application")


def admit_rule(record: dict, catalog: dict) -> None:
    try:
        validate_route_coexistence([*catalog["access_rules"], {**record, "status": "active"}])
    except CatalogIntegrityError as error:
        # Both messages are fixed; no caller value or retained token is exposed.
        raise ValueError(str(error)) from None


def render_route(rule: dict, credential: dict, principal_id: str) -> dict:
    from serverware import npm_metadata
    validate_rule(rule, credential)
    return {"id": rule["route_id"], "principals": [principal_id],
        "match": {"scheme": "https", "host": "registry.npmjs.org", "port": 443,
            "methods": ["GET"], "paths": ["/{package}"]},
        "credentialRef": credential["id"], "adapter": {"type": npm_metadata.ADAPTER, "config": {
            "credentialBinding": {"credentialType": "static", "provider": "operator-demo",
                "subjects": [credential["provider_subject"]], "secretClass": "bearerToken"},
            "packages": list(rule["packages"]), "request": npm_metadata.request_profile(),
            "response": npm_metadata.response_profile()}},
        "constraints": [npm_metadata.response_envelope(rule["route_id"] + ".envelope")]}


def public_fields(rule: dict) -> dict:
    validate_shape(rule)
    return {"operation_bundle": BUNDLE, "packages": list(rule["packages"])}


def capability() -> dict:
    from serverware import operator_demo
    return {"schema": "serverware.operatorNpmMetadata/v1", "connection_type": CONNECTION,
        "create_credential_path": "/api/operator-demo/credentials/npm-token",
        "create_rule_path": "/api/operator-demo/access-rules/npm-metadata", "registry_origin": ORIGIN,
        "destination_allowed": ORIGIN in operator_demo.settings()["allowed_upstreams"],
        "operation_bundles": [BUNDLE], "sdk_auth_token": SDK_TOKEN, "placeholder": PLACEHOLDER,
        "response_mode": RESPONSE_MODE, "source_pair_required": True, "metadata_only": True,
        "max_active_rules_per_application": 1}
