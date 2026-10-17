"""Typed exact-destination ECR permissions, always whole-publication reviewed."""
from __future__ import annotations

from catchplate import ecr_publication_policy as wire
from catchplate import operator_catalog_aws as aws
from catchplate.operator_catalog_schema import CatalogConflict, CatalogIntegrityError

BUNDLE = "aws_ecr_publish_v1"
RESPONSE_MODE = "aws_ecr_publication_json_v1"
INPUT_MODE = "aws_ecr_signing_v1"
CREATE_PATH = "/api/operator-demo/access-rules/aws-ecr-publication"
_SCOPE = ("registry_id", "region", "repository_name", "image_tag")
_FIELDS = frozenset({"id", "ordinal", "version", "route_id", "name", "application_id", "credential_id",
    "operation_bundle", *_SCOPE, "approval_mode", "upstream_url", "methods", "request_fields",
    "response_fields", "query_keys", "allowed_headers", "response_mode", "credential_input",
    "created_at", "status", "revoked_at"})


def selected(rule):
    return rule.get("operation_bundle") == BUNDLE


def _derived(region):
    return {"upstream_url": "https://" + wire.host(region) + "/", "methods": ["POST"],
        "request_fields": [], "response_fields": [], "query_keys": [],
        "allowed_headers": list(wire.REQUEST_HEADERS), "response_mode": RESPONSE_MODE,
        "credential_input": INPUT_MODE}


def validate_shape(rule):
    try:
        if not selected(rule) or set(rule) - _FIELDS or rule.get("approval_mode") != "host_review_v1":
            raise ValueError()
        wire.validate_scope(*(rule[key] for key in _SCOPE))
        if any(rule.get(key) != value for key, value in _derived(rule["region"]).items()):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise CatalogIntegrityError("ECR publication permission refused") from None


def record_fields(payload):
    result = payload.model_dump(exclude={"expected_revision", "expected_policy_hash"})
    result.update(_derived(result["region"]))
    validate_shape(result)
    return result


def validate_rule(rule, credential):
    validate_shape(rule)
    aws.validate_credential(credential)


def validate_route_coexistence(rules):
    scopes = set()
    for rule in rules:
        if rule.get("status") != "active" or not selected(rule):
            continue
        validate_shape(rule)
        # Regional ECR operations all use POST /. The generic route selector
        # must never choose a credential by first matching an overlapping rule.
        scope = (rule["application_id"], rule["region"])
        if scope in scopes:
            raise CatalogIntegrityError("ambiguous ECR publication permission")
        scopes.add(scope)


def admit_rule(rule, catalog):
    try:
        validate_route_coexistence([*catalog["access_rules"], {**rule, "status": "active"}])
    except CatalogIntegrityError:
        raise CatalogConflict("This client already has an ECR permission in this region") from None


def credential_policy(credential):
    aws.validate_credential(credential)
    return {"id": credential["id"], "credentialType": "static", "provider": "operator-demo",
        "providerSubject": credential["provider_subject"], "injection": dict(wire.INJECTION)}


def render_route(rule, credential, principal_id):
    validate_rule(rule, credential)
    return {"id": rule["route_id"], "principals": [principal_id],
        "match": {"scheme": "https", "host": wire.host(rule["region"]), "port": 443,
            "methods": ["POST"], "paths": ["/"]}, "credentialRef": credential["id"],
        "adapter": {"type": wire.ADAPTER, "config": {
            "credentialBinding": {"credentialType": "static", "provider": "operator-demo",
                "subjects": [credential["provider_subject"]], "secretClass": "awsSigV4"},
            "registryId": rule["registry_id"], "region": rule["region"],
            "repositoryName": rule["repository_name"], "imageTag": rule["image_tag"],
            "approval": dict(wire.APPROVAL), "request": wire.request_profile(), "response": wire.response_profile()}},
        "constraints": [wire.response_envelope(rule["route_id"] + ".envelope")]}


def public_fields(rule):
    validate_shape(rule)
    return {"operation_bundle": BUNDLE, **{key: rule[key] for key in _SCOPE}, "publication_approval_required": True}


def gate_descriptor_matches(value):
    return type(value) is dict and value == wire.GATE_DESCRIPTOR and all(type(item) is str for item in value.values())


def _available(policy_hash):
    try:
        from catchplate import operator_demo_store as store, operator_publication, operator_ecr_publications
        operator_publication.assert_not_held()
        if not operator_ecr_publications.readiness():
            return False
        observed = store.loaded_gate_status()
        if (type(observed) is not dict or observed.get("ok") is not True
                or observed.get("policy_hash") != policy_hash
                or not gate_descriptor_matches(observed.get("operator_ecr_publication"))):
            return False
        with store._require().metadata_connection() as conn:
            rows = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchall()
        return len(rows) == 1 and rows[0][0] == policy_hash
    except Exception:
        return False


def require_available(policy_hash):
    if not _available(policy_hash):
        raise CatalogConflict("ECR publication owner and matching proxy are unavailable")


def capability(policy_hash):
    if not _available(policy_hash):
        return None
    return {"schema": "catchplate.operatorEcrPublication/v1", "connection_type": aws.CONNECTION,
        "create_rule_path": CREATE_PATH, "operation_bundles": [BUNDLE], "approval_mode": "host_review_v1",
        "publication_approval_required": True, "credential_input": INPUT_MODE, "response_mode": RESPONSE_MODE,
        "route_scope": "one_per_client_region",
        "max_request_bytes": wire.MAX_REQUEST_BYTES, "max_response_bytes": wire.MAX_RESPONSE_BYTES,
        "automatic_retries": False, "source_pair_required": True}
