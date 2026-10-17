"""One explicit npm publish permission and its package-metadata prerequisite.

Both signed routes belong to one retained catalog rule. Publishing hours bind
only the PUT; no existing metadata or legacy npm write grant is broadened.
"""
from __future__ import annotations

from urllib.parse import urlsplit
import uuid

from catchplate import operator_catalog_npm as metadata
from catchplate.operator_catalog_schema import CatalogIntegrityError

BUNDLE = "npm_publish_v1"
ORIGIN = metadata.ORIGIN
RESPONSE_MODE = "npm_publish_json_v1"
_FIELDS = {"name", "application_id", "credential_id", "operation_bundle", "package", "tag",
    "publishing_window", "upstream_url", "methods", "request_fields", "response_fields",
    "query_keys", "allowed_headers", "response_mode", "credential_input", "placeholder"}
_RETAINED = {"id", "ordinal", "version", "route_id", "created_at", "status", "revoked_at", "approval_mode"}


def selected(rule: dict) -> bool:
    return rule.get("operation_bundle") == BUNDLE


def _derived_fields() -> dict:
    from catchplate import npm_publish
    return {"upstream_url": ORIGIN + "/", "methods": ["PUT"], "request_fields": [],
        "response_fields": [], "query_keys": [],
        "allowed_headers": list(npm_publish.request_profile()["allowedHeaders"]),
        "response_mode": RESPONSE_MODE, "credential_input": "replace_exact",
        "placeholder": metadata.PLACEHOLDER}


def record_fields(payload) -> dict:
    record = payload.model_dump(exclude={"expected_revision", "expected_policy_hash"})
    record.update(_derived_fields())
    validate_shape(record)
    return record


def protocol_window(window):
    """Public settings never select a timezone; the protocol receives fixed UTC."""
    if window is None:
        return None
    if type(window) is not dict or set(window) != {"start", "end"}:
        raise ValueError("operator npm publishing window refused")
    return {"timezone": "UTC", "start": window["start"], "end": window["end"]}


def validate_shape(rule: dict) -> None:
    from catchplate import npm_publish
    if (not selected(rule) or not _FIELDS <= set(rule) or set(rule) - (_FIELDS | _RETAINED)):
        raise CatalogIntegrityError("operator npm publish contract refused")
    try:
        npm_publish.validate_package(rule["package"])
        npm_publish.validate_tag(rule["tag"])
        npm_publish.validate_window(protocol_window(rule["publishing_window"]))
        expected = _derived_fields()
    except (KeyError, TypeError, ValueError) as error:
        raise CatalogIntegrityError("operator npm publish authority refused") from error
    if any(rule[key] != value for key, value in expected.items()):
        raise CatalogIntegrityError("operator npm publish derived profile refused")


def validate_rule(rule: dict, credential: dict) -> None:
    validate_shape(rule)
    metadata.validate_credential(credential)


def route_ids(rule: dict) -> tuple[str, str]:
    """Derive aliases only from a validated exact retained publish identity."""
    validate_shape(rule)
    try:
        identifier = rule["id"]
        if str(uuid.UUID(identifier)) != identifier or rule["route_id"] != "operator." + identifier:
            raise ValueError("invalid identity")
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise CatalogIntegrityError("operator npm publish route identity refused") from error
    return rule["route_id"], rule["route_id"] + ".metadata"


def validate_route_coexistence(rules: list[dict]) -> None:
    # Preserve metadata-only's established GET overlap behavior, including its
    # compatibility with an unrelated generic PUT. Publish owns both methods.
    metadata.validate_route_coexistence(rules)
    active = [rule for rule in rules if rule.get("status") == "active"]
    applications, publishers = set(), set()
    for rule in active:
        if not (metadata.selected(rule) or selected(rule)):
            continue
        application = rule["application_id"]
        if application in applications:
            raise CatalogIntegrityError("only one active npm permission is supported per application")
        applications.add(application)
        if selected(rule):
            publishers.add(application)
    for rule in active:
        if (selected(rule) or metadata.selected(rule) or rule["application_id"] not in publishers
                or not {"GET", "PUT"}.intersection(rule.get("methods", []))):
            continue
        try:
            target = urlsplit(rule["upstream_url"])
            overlap = (target.scheme == "https" and target.hostname == "registry.npmjs.org"
                and target.port in {None, 443} and target.path.startswith("/")
                and len(target.path) > 1 and "/" not in target.path[1:])
        except (KeyError, TypeError, ValueError) as error:
            raise CatalogIntegrityError("operator npm publish route coexistence refused") from error
        if overlap:
            raise CatalogIntegrityError("npm publish permission conflicts with a registry GET or PUT rule")


def admit_rule(record: dict, catalog: dict) -> None:
    try:
        validate_route_coexistence([*catalog["access_rules"], {**record, "status": "active"}])
    except CatalogIntegrityError as error:
        raise ValueError(str(error)) from None


def render_routes(rule: dict, credential: dict, principal_id: str) -> list[dict]:
    from catchplate import npm_metadata, npm_publish
    validate_rule(rule, credential)
    primary, companion = route_ids(rule)
    binding = {"credentialType": "static", "provider": "operator-demo",
        "subjects": [credential["provider_subject"]], "secretClass": "bearerToken"}
    constraints = [npm_publish.response_envelope(primary + ".envelope")]
    window = rule["publishing_window"]
    if window is not None:
        constraints.append(npm_publish.time_window_constraint(primary + ".publishing-window", protocol_window(window)))
    return [{"id": primary, "principals": [principal_id],
        "match": {"scheme": "https", "host": "registry.npmjs.org", "port": 443,
            "methods": ["PUT"], "paths": ["/{package}"]},
        "credentialRef": credential["id"], "adapter": {"type": npm_publish.ADAPTER, "config": {
            "credentialBinding": binding, "package": rule["package"], "tag": rule["tag"],
            "request": npm_publish.request_profile(), "response": npm_publish.response_profile()}},
        "constraints": constraints},
        {"id": companion, "principals": [principal_id],
        "match": {"scheme": "https", "host": "registry.npmjs.org", "port": 443,
            "methods": ["GET"], "paths": ["/{package}"]},
        "credentialRef": credential["id"], "adapter": {"type": npm_metadata.ADAPTER, "config": {
            "credentialBinding": {**binding, "subjects": list(binding["subjects"])},
            "packages": [rule["package"]], "request": npm_metadata.request_profile(),
            "response": npm_metadata.response_profile()}},
        "constraints": [npm_metadata.response_envelope(companion + ".envelope")]}]


def public_fields(rule: dict) -> dict:
    validate_shape(rule)
    return {"operation_bundle": BUNDLE, "package": rule["package"], "tag": rule["tag"],
        "publishing_window": None if rule["publishing_window"] is None else dict(rule["publishing_window"])}


def capability() -> dict:
    from catchplate import npm_publish, operator_demo
    return {"schema": "catchplate.operatorNpmPublish/v1", "connection_type": metadata.CONNECTION,
        "create_rule_path": "/api/operator-demo/access-rules/npm-publish", "registry_origin": ORIGIN,
        "destination_allowed": ORIGIN in operator_demo.settings()["allowed_upstreams"],
        "operation_bundles": [BUNDLE], "sdk_auth_token": metadata.SDK_TOKEN,
        "placeholder": metadata.PLACEHOLDER, "response_mode": RESPONSE_MODE,
        "source_pair_required": True, "max_active_rules_per_application": 1,
        "read_metadata_included": True, "default_tag": "latest", "publishing_window_timezone": "UTC",
        "max_request_body_bytes": npm_publish.MAX_REQUEST_BODY_BYTES,
        "max_tarball_bytes": npm_publish.MAX_TARBALL_BYTES}
