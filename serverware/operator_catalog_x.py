"""Explicit app-only X username grants, separate from X OAuth and generic rules.

The connection marker is public catalog metadata, not verified X identity or
entitlement. Secrets retain the existing operator-demo encrypted static custody.
"""
from __future__ import annotations

import re

from serverware import x_app_read
from serverware.operator_catalog_schema import CatalogConflict, CatalogIntegrityError

CONNECTION = "x_app_bearer_v1"
BUNDLE = "x_username_read_v1"
ORIGIN = x_app_read.ORIGIN
RESPONSE_MODE = "x_app_read_json_v1"
SDK_TOKEN = x_app_read.PLACEHOLDER
PLACEHOLDER = x_app_read.REPLACEMENT["expectedValue"]
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GATE_DESCRIPTOR = {"schema": "serverware.operatorXAppReadGate/v1",
    "adapter": "x.app_read.v1", "operation": "x.username.read"}

_RULE_FIELDS = frozenset({
    "name", "application_id", "credential_id", "operation_bundle", "username",
    "upstream_url", "methods", "request_fields", "response_fields", "query_keys",
    "allowed_headers", "response_mode", "credential_input", "placeholder",
    "id", "route_id", "created_at", "status", "ordinal", "version", "revoked_at",
})


def validate_token(value: str) -> str:
    """Opaque bounded bearer syntax only; never a provider validation request."""
    return x_app_read.validate_token(value)


def selected(rule: dict) -> bool:
    return rule.get("operation_bundle") == BUNDLE


def validate_credential(record: dict, metadata: dict | None = None) -> bool:
    if (record.get("connection_type") != CONNECTION or record.get("auth_type") != "bearer"
            or record.get("header_name") != "Authorization"
            or metadata is not None and metadata.get("connection_type") != CONNECTION):
        raise CatalogIntegrityError("catalog X app bearer binding refused")
    return True


def _derived_fields(username: str) -> dict:
    username = x_app_read.validate_username(username)
    request = x_app_read.request_profile()
    return {"upstream_url": ORIGIN + x_app_read.route_paths(username)[0],
        "methods": ["GET"], "request_fields": [], "response_fields": [], "query_keys": [],
        "allowed_headers": list(request["allowedHeaders"]), "response_mode": RESPONSE_MODE,
        "credential_input": "replace_exact", "placeholder": PLACEHOLDER}


def record_fields(payload) -> dict:
    record = payload.model_dump(exclude={"expected_revision", "expected_policy_hash"})
    record.update(_derived_fields(record["username"]))
    validate_shape(record)
    return record


def validate_shape(rule: dict) -> None:
    if not selected(rule) or set(rule) - _RULE_FIELDS:
        raise CatalogIntegrityError("operator X username contract refused")
    try:
        expected = _derived_fields(rule["username"])
    except (KeyError, TypeError, ValueError) as error:
        raise CatalogIntegrityError("operator X username contract refused") from error
    if any(rule.get(key) != value for key, value in expected.items()):
        raise CatalogIntegrityError("operator X derived profile refused")


def validate_rule(rule: dict, credential: dict) -> None:
    validate_shape(rule)
    validate_credential(credential)


def validate_route_coexistence(rules: list[dict]) -> None:
    """Two typed grants must not silently select the first credential."""
    selected_paths = set()
    for rule in rules:
        if rule.get("status") != "active" or not selected(rule):
            continue
        validate_shape(rule)
        key = (rule["application_id"], rule["username"])
        if key in selected_paths:
            raise CatalogIntegrityError("duplicate active X username permission refused")
        selected_paths.add(key)


def admit_rule(record: dict, catalog: dict) -> None:
    try:
        validate_route_coexistence([*catalog["access_rules"], {**record, "status": "active"}])
    except CatalogIntegrityError:
        raise CatalogConflict("X username permission already exists") from None


def render_route(rule: dict, credential: dict, principal_id: str) -> dict:
    validate_rule(rule, credential)
    return {"id": rule["route_id"], "principals": [principal_id],
        "match": {"scheme": "https", "host": x_app_read.HOST, "port": 443,
            "methods": ["GET"], "paths": list(x_app_read.route_paths(rule["username"]))},
        "credentialRef": credential["id"], "adapter": {"type": x_app_read.ADAPTER, "config": {
            "credentialBinding": {"credentialType": "static", "provider": "operator-demo",
                "subjects": [credential["provider_subject"]], "secretClass": "bearerToken"},
            "username": rule["username"], "request": x_app_read.request_profile(),
            "response": x_app_read.response_profile()}},
        "constraints": [x_app_read.response_envelope(rule["route_id"] + ".envelope")]}


def public_fields(rule: dict) -> dict:
    validate_shape(rule)
    return {"operation_bundle": BUNDLE, "username": rule["username"]}


def gate_descriptor_matches(value) -> bool:
    """An exact compatibility declaration, not provider or SDK acceptance."""
    return (type(value) is dict and value == _GATE_DESCRIPTOR
        and all(type(item) is str for item in value.values()))


def _available(policy_hash: str) -> bool:
    """Fresh point-in-time compatibility; never poll inside caller ownership.

    Managed mode joins the descriptor to the same health response as its
    original app/gate identity and binary checks. Legacy mode observes once,
    then rereads the local policy. The mutation's existing CAS remains required
    after this observer returns, before any credential or catalog write.
    """
    try:
        if type(policy_hash) is not str or _SHA.fullmatch(policy_hash) is None:
            return False
        from serverware import operator_demo_store as store, operator_publication as publication
        from serverware import operator_google_managed_config as managed
        publication.assert_not_held()
        if managed.enabled():
            from serverware import operator_google_managed_readiness as readiness
            observed = readiness.observe_x()
            return (observed["ready"] is True
                and observed["policy_hash"] == observed["loaded_policy_hash"] == policy_hash)
        observed = store.loaded_gate_status()
        if (type(observed) is not dict or observed.get("ok") is not True
                or observed.get("policy_hash") != policy_hash
                or not gate_descriptor_matches(observed.get("operator_x_app_read"))):
            return False
        # This local read starts only after the bounded health request closed.
        with store._require().metadata_connection() as conn:
            rows = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchall()
            return len(rows) == 1 and rows[0][0] == policy_hash
    except Exception:
        return False


def require_available(policy_hash: str) -> None:
    if not _available(policy_hash):
        raise CatalogConflict("X app read gate unavailable") from None


def capability(policy_hash: str) -> dict | None:
    if not _available(policy_hash):
        return None
    return _capability()


def _capability() -> dict:
    """Display DTO only; caller owns its fresh, policy-bound observation."""
    from serverware import operator_demo
    return {"schema": "serverware.operatorXAppRead/v1", "connection_type": CONNECTION,
        "create_credential_path": "/api/operator-demo/credentials/x-app-bearer",
        "create_rule_path": "/api/operator-demo/access-rules/x-username", "api_origin": ORIGIN,
        "destination_allowed": ORIGIN in operator_demo.settings()["allowed_upstreams"],
        "operation_bundles": [BUNDLE], "sdk_auth_token": SDK_TOKEN, "placeholder": PLACEHOLDER,
        "response_mode": RESPONSE_MODE, "source_pair_required": True}
