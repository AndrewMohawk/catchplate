"""Ordinary X posting grants for explicitly connected OAuth accounts.

The typed wire profile is shared with the actual proxy. This catalog slice does
not implement counter storage or convert app-only bearer keys into accounts.
An omitted limit preserves the exact legacy unbounded record and route.
"""
from __future__ import annotations

from serverware import x_post
from serverware.operator_catalog_schema import CatalogConflict, CatalogIntegrityError

BUNDLE = "x_text_post_v1"
RESPONSE_MODE = "x_post_json_v1"
ORIGIN = x_post.ORIGIN
QUOTA_FIELD = "daily_post_attempt_limit"
QUOTA_DESCRIPTOR = {"schema": "serverware.operatorXPostAttemptQuota/v1",
    "field": QUOTA_FIELD, "period": "utc_day", "scope": "verified_x_account",
    "unit": "posting_attempt", "minimum": 1, "maximum": 1_000_000_000}
_GATE_DESCRIPTOR = {"schema": "serverware.operatorXPostGate/v1",
    "adapter": x_post.ADAPTER, "operation": x_post.OPERATION}
_RULE_FIELDS = frozenset({"name", "application_id", "credential_id", "operation_bundle",
    "upstream_url", "methods", "request_fields", "response_fields", "query_keys",
    "allowed_headers", "response_mode", "credential_input", "placeholder",
    "id", "route_id", "created_at", "status", "ordinal", "version", "revoked_at", QUOTA_FIELD})


def selected(rule: dict) -> bool:
    return rule.get("operation_bundle") == BUNDLE


def _derived_fields() -> dict:
    return {"upstream_url": ORIGIN + x_post.PATH, "methods": ["POST"],
        "request_fields": [], "response_fields": [], "query_keys": [],
        "allowed_headers": list(x_post.REQUEST_HEADERS), "response_mode": RESPONSE_MODE,
        "credential_input": "replace_exact", "placeholder": x_post.REPLACEMENT["expectedValue"]}


def record_fields(payload) -> dict:
    record = payload.model_dump(exclude={"expected_revision", "expected_policy_hash"}, exclude_none=True)
    record.update(_derived_fields())
    validate_shape(record)
    return record


def validate_shape(rule: dict) -> None:
    # The only optional quota field is a closed integer, never null or bool.
    if (type(rule) is not dict or not selected(rule) or set(rule) - _RULE_FIELDS
            or (QUOTA_FIELD in rule and (type(rule[QUOTA_FIELD]) is not int
                or not 1 <= rule[QUOTA_FIELD] <= QUOTA_DESCRIPTOR["maximum"]))
            or any(rule.get(key) != value for key, value in _derived_fields().items())):
        raise CatalogIntegrityError("operator X posting contract refused")


def validate_rule(rule: dict, credential: dict) -> None:
    from serverware import operator_catalog_x_oauth as account
    validate_shape(rule)
    account.validate_identity(credential)


def validate_route_coexistence(rules: list[dict], credentials: list[dict]) -> None:
    # Same endpoint/principal cannot silently select another account. Account
    # quotas do not split at credential IDs, route IDs, or OAuth client IDs.
    by_id = {credential["id"]: credential for credential in credentials}
    selected_applications = set()
    account_limits = {}
    for rule in rules:
        if rule.get("status") != "active" or not selected(rule):
            continue
        validate_shape(rule)
        if rule["application_id"] in selected_applications:
            raise CatalogIntegrityError("duplicate active X posting permission refused")
        selected_applications.add(rule["application_id"])
        credential = by_id.get(rule["credential_id"])
        if credential is None:
            raise CatalogIntegrityError("X posting account binding refused")
        validate_rule(rule, credential)
        subject = credential["provider_subject"]
        maximum = rule.get(QUOTA_FIELD)
        if subject in account_limits and account_limits[subject] != maximum:
            raise CatalogIntegrityError("X account posting-attempt limits disagree")
        account_limits[subject] = maximum


def admit_rule(record: dict, catalog: dict) -> None:
    try:
        validate_route_coexistence([*catalog["access_rules"], {**record, "status": "active"}],
            catalog["credentials"])
    except CatalogIntegrityError:
        raise CatalogConflict("X posting permissions must use one account-wide attempt limit") from None


def render_route(rule: dict, credential: dict, principal_id: str) -> dict:
    from serverware import operator_catalog_x_oauth as account
    validate_rule(rule, credential)
    constraints = [x_post.response_envelope(rule["route_id"] + ".envelope")]
    if QUOTA_FIELD in rule:
        constraints.append(x_post.quota_constraint(rule[QUOTA_FIELD]))
    return {"id": rule["route_id"], "principals": [principal_id],
        "match": {"scheme": "https", "host": x_post.HOST, "port": 443,
            "methods": ["POST"], "paths": x_post.route_paths()},
        "credentialRef": credential["id"], "adapter": {"type": x_post.ADAPTER, "config": {
            "credentialBinding": account.route_binding(credential),
            "request": x_post.request_profile(), "response": x_post.response_profile()}},
        "constraints": constraints}


def public_fields(rule: dict) -> dict:
    validate_shape(rule)
    return {"operation_bundle": BUNDLE,
        **({QUOTA_FIELD: rule[QUOTA_FIELD]} if QUOTA_FIELD in rule else {})}


def gate_descriptor_matches(value) -> bool:
    return (type(value) is dict and value == _GATE_DESCRIPTOR
        and all(type(item) is str for item in value.values()))


def quota_descriptor_matches(value) -> bool:
    return (type(value) is dict and value == QUOTA_DESCRIPTOR
        and all(type(value[key]) is type(expected) for key, expected in QUOTA_DESCRIPTOR.items()))


def require_available(expected_policy_hash: str, *, quota: bool = False) -> dict:
    """Fresh observed pair, not a fabricated source-only capability."""
    from serverware import operator_x_readiness
    observed = operator_x_readiness.observe_quota() if quota else operator_x_readiness.observe()
    if (observed.get("ready") is not True or observed.get("policy_hash") != expected_policy_hash
            or observed.get("loaded_policy_hash") != expected_policy_hash
            or (quota and observed.get("daily_quota_available") is not True)):
        raise CatalogConflict("operator X posting unavailable")
    return observed


def _capability(*, daily_quota_available: bool = False) -> dict:
    """Display only; callers must supply the matching fresh app/gate admission."""
    from serverware import operator_demo
    from serverware.operator_catalog_x_oauth import CONNECTION
    return {"schema": "serverware.operatorXPost/v1", "connection_type": CONNECTION,
        "create_rule_path": "/api/operator-demo/access-rules/x-post", "api_origin": ORIGIN,
        "destination_allowed": ORIGIN in operator_demo.settings()["allowed_upstreams"],
        "operation_bundles": [BUNDLE], "sdk_auth_token": x_post.PLACEHOLDER,
        "placeholder": x_post.REPLACEMENT["expectedValue"], "response_mode": RESPONSE_MODE,
        "source_pair_required": True, "daily_quota_available": daily_quota_available is True,
        **({"daily_quota": dict(QUOTA_DESCRIPTOR)} if daily_quota_available is True else {})}
