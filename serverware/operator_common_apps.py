"""Versioned common-service recipes compiled into existing generic REST policy.

These are scoped operations, not blanket access to every API of a named service.
Only this module derives their retained authority; browser fields are not trusted.
No provider request, discovery, migration, or credential decryption occurs here.
"""
from __future__ import annotations

from copy import deepcopy
import re
from urllib.parse import urlsplit

from serverware.operator_catalog_schema import CatalogIntegrityError

SCHEMA = "serverware.operatorCommonApps/v1"
RESPONSE_MODE = "unfiltered_json_or_empty_v2"
LIMITS = {"request_body_bytes": 65536, "response_body_bytes": 1048576,
    "error_body_bytes": 65536, "streaming": False}


def presets() -> list[dict]:
    from serverware.operator_common_apps_ai import PRESETS as ai
    from serverware.operator_common_apps_services import PRESETS as services
    return ai + services


def preset(identifier: str) -> dict:
    if type(identifier) is not str:
        raise ValueError("common app identifier refused")
    result = next((item for item in presets() if item["id"] == identifier), None)
    if result is None:
        raise ValueError("unknown common app")
    return result


def operation(identifier: str, operation_id: str) -> tuple[dict, dict]:
    app = preset(identifier)
    result = next((item for item in app["operations"] if item["id"] == operation_id), None)
    if result is None:
        raise ValueError("unknown common app operation")
    return app, result


def selected(record: dict) -> bool:
    return "app_preset" in record or "app_operation" in record


def validate_credential(record: dict, metadata: dict | None = None) -> bool:
    marked = "app_preset" in record
    if "app_operation" in record:
        raise CatalogIntegrityError("credential cannot contain an operation marker")
    if not marked and (metadata is None or "app_preset" not in metadata):
        return False
    try:
        app = preset(record["app_preset"])
        if (record.get("auth_type") != app["auth_type"]
                or record.get("header_name") != app["header_name"]
                or "connection_type" in record or "app_operation" in record
                or metadata is not None and (
                    metadata.get("app_preset") != app["id"] or "connection_type" in metadata
                    or app["auth_type"] == "header"
                    and metadata.get("injection_name") != app["header_name"])):
            raise ValueError("common app credential differs")
    except (KeyError, TypeError, ValueError) as error:
        raise CatalogIntegrityError("common app credential binding refused") from error
    return True


def validate_credential_input(identifier: str, auth_type: str, header_name: str | None) -> None:
    app = preset(identifier)
    effective_header = "Authorization" if auth_type == "bearer" else header_name
    if auth_type != app["auth_type"] or effective_header != app["header_name"]:
        raise ValueError("credential placement does not match the common app")


def validate_secret(identifier: str, secret: str) -> str:
    preset(identifier)
    if (type(secret) is not str or not 1 <= len(secret) <= 8192
            or any(ord(char) < 33 or ord(char) > 126 for char in secret)):
        raise ValueError("common app requires an opaque printable token without whitespace")
    return secret


def scope_values(spec: dict, scope: dict) -> dict:
    fields = spec.get("scope_fields", [])
    if type(scope) is not dict or set(scope) != {item["key"] for item in fields}:
        raise ValueError("common app scope fields differ")
    result = {}
    for field in fields:
        value = scope[field["key"]]
        if field["type"] == "number":
            if type(value) is not int or not field["min"] <= value <= field["max"]:
                raise ValueError("common app numeric scope refused")
        elif (type(value) is not str or not 1 <= len(value) <= 256
                or not value.isascii() or re.fullmatch(field["pattern"], value) is None):
            raise ValueError("common app text scope refused")
        result[field["key"]] = value
    return result


def resolve(value, scope: dict):
    """Substitute only an explicit data marker; never evaluate caller text."""
    if type(value) is dict:
        if set(value) == {"$scope"}:
            return scope[value["$scope"]]
        return {key: resolve(item, scope) for key, item in value.items()}
    if type(value) is list:
        return [resolve(item, scope) for item in value]
    return deepcopy(value)


def derived_fields(identifier: str, operation_id: str, scope: dict) -> dict:
    app, spec = operation(identifier, operation_id)
    scope = scope_values(spec, scope)
    target = spec["origin"] + spec["path_template"].format(**scope)
    parsed = urlsplit(target)
    if (parsed.scheme != "https" or parsed.query or parsed.fragment or parsed.username
            or parsed.password or target != spec["origin"] + parsed.path):
        raise ValueError("common app target refused")
    return {"upstream_url": target, "methods": deepcopy(spec["methods"]),
        "request_fields": deepcopy(spec.get("request_fields", [])), "response_fields": [],
        "query_keys": deepcopy(spec.get("query_keys", [])),
        "allowed_headers": deepcopy(spec.get("allowed_headers", [])),
        "response_mode": RESPONSE_MODE, "credential_input": "replace_exact",
        "placeholder": app["placeholder"]}


def record_fields(payload) -> dict:
    record = payload.model_dump(exclude={"expected_revision", "expected_policy_hash", "operation"})
    record["app_operation"] = payload.operation
    record.update(derived_fields(payload.app_preset, payload.operation, payload.scope))
    validate_shape(record)
    return record


def validate_shape(rule: dict) -> None:
    try:
        expected = derived_fields(rule["app_preset"], rule["app_operation"], rule["scope"])
        if (any(rule.get(key) != value for key, value in expected.items())
                or any(key in rule for key in ("operation_bundle", "request_body_mode", "query_mode", "age_policy"))):
            raise ValueError("common app derived fields differ")
    except (KeyError, TypeError, ValueError) as error:
        raise CatalogIntegrityError("common app operation contract refused") from error


def validate_rule(rule: dict, credential: dict) -> None:
    validate_shape(rule)
    if not validate_credential(credential) or rule["app_preset"] != credential["app_preset"]:
        raise CatalogIntegrityError("common app operation requires its matching credential")


def apply_route(rule: dict, credential: dict, route: dict) -> None:
    validate_rule(rule, credential)
    _, spec = operation(rule["app_preset"], rule["app_operation"])
    request = route["adapter"]["config"]["request"]
    # Encoding negotiation is removed before authorization and dispatch. The
    # upstream client already requests identity, avoiding compressed SDK bodies.
    request["discardHeaders"] = ["accept-encoding"]
    request["valueRules"] = resolve(spec.get("value_rules", []), rule["scope"])
    if spec.get("required_headers"):
        request["requiredHeaders"] = resolve(spec["required_headers"], rule["scope"])
    field_rules = resolve(spec.get("field_rules", {}), rule["scope"])
    if rule["request_fields"]:
        body = next(item for item in route["constraints"] if item.get("type") == "jsonBody")
        body["fields"] = field_rules
        body["requiredFields"] = [key for key, value in field_rules.items() if value.get("required") is True]
    elif field_rules:
        raise CatalogIntegrityError("common app body rules lack an allowed body")


def credential_injection(record: dict) -> dict:
    validate_credential(record)
    app = preset(record["app_preset"])
    if app["auth_type"] == "header":
        return {"type": "header", "name": app["header_name"], "prefix": ""}
    result = {"type": "bearer", "header": "Authorization"}
    if "injection_prefix" in app:
        result["prefix"] = app["injection_prefix"]
    return result


def public_fields(record: dict) -> dict:
    validate_shape(record)
    return {"app_preset": record["app_preset"], "app_operation": record["app_operation"],
        "scope": deepcopy(record["scope"])}


def capability() -> dict:
    from serverware import operator_demo
    allowed = operator_demo.settings()["allowed_upstreams"]
    result = []
    for source in presets():
        app = deepcopy(source)
        app["destination_allowed"] = all(item["origin"] in allowed for item in app["operations"])
        for spec in app["operations"]:
            # Legacy descriptors remain available for existing-rule validation
            # and client downloads, but are not choices for a new permission.
            spec.setdefault("available_for_creation", True)
            spec.update(response_mode=RESPONSE_MODE, credential_input="replace_exact",
                placeholder=app["placeholder"], response_fields=[], limits=deepcopy(LIMITS),
                destination_allowed=spec["origin"] in allowed)
            spec.setdefault("request_headers", {})
            spec.setdefault("example_body", None)
            spec.setdefault("notes", [])
        result.append(app)
    return {"schema": SCHEMA, "create_credential_path": "/api/operator-demo/credentials",
        "create_rule_path": "/api/operator-demo/access-rules/common-app", "presets": result,
        "source_pair_required": True}
