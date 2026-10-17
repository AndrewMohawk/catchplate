"""Closed ordinary ECR signing/publication policy; no custody or dispatch."""
from __future__ import annotations

import re
from uuid import UUID

from catchplate import ecr_sdk_protocol

ADAPTER = "aws.ecr.publish.v1"
OPERATION = "aws.ecr.publish"
MODE = "awsEcrPublicationJsonV1"
CONTENT_TYPE_POLICY = "awsEcrPublicationJsonUtf8V1"
INJECTION = {"type": "awsEcrSigningV1"}
APPROVAL = {"mode": "host_review_v1", "scope": "publication"}
OPERATION_FIELDS = frozenset({"operation", "registryId", "region", "repositoryName",
    "imageTag", "publicationId", "action", "requestBodySha256"})
GATE_DESCRIPTOR = {"schema": "catchplate.operatorEcrPublicationGate/v1",
    "adapter": ADAPTER, "operation": OPERATION, "signing": "exact_request_lease_v1",
    "approval": "host_publication_review_v1"}
REQUEST_HEADERS = ["amz-sdk-invocation-id", "amz-sdk-request", "authorization",
    "user-agent", "x-amz-date", "x-amz-target"]
MAX_REQUEST_BYTES = 16777216
MAX_RESPONSE_BYTES = 26214400
MAX_ERROR_BYTES = 65536
STATUSES = [200, 400, 401, 403, 404, 429, 500, 502, 503, 504]
CONTENT_TYPES = ["application/x-amz-json-1.1", "application/json"]


def _need(value):
    if not value:
        raise ValueError("ECR publication policy refused")


def validate_scope(registry_id, region, repository_name, image_tag):
    ecr_sdk_protocol.Scope(registry_id, region, repository_name)
    _need(type(image_tag) is str and re.fullmatch(r"[!-~]{1,300}", image_tag) is not None)


def host(region):
    ecr_sdk_protocol.Scope("123456789012", region, "scope-check")
    return "api.ecr." + region + ".amazonaws.com"


def request_profile():
    return {"allowedHeaders": list(REQUEST_HEADERS), "discardHeaders": ["accept-encoding"],
        "allowedQueryKeys": [], "allowedMediaTypes": ["application/x-amz-json-1.1"],
        "maxBodyBytes": MAX_REQUEST_BYTES, "valueRules": []}


def response_profile():
    return {"mode": MODE, "maxBodyBytes": MAX_RESPONSE_BYTES,
        "contentTypes": [CONTENT_TYPES[0]], "allowedHeaders": [],
        "error": {"mode": MODE, "maxBodyBytes": MAX_ERROR_BYTES,
            "contentTypes": list(CONTENT_TYPES), "allowedHeaders": [], "onInvalid": "block"}}


def response_envelope(identifier):
    return {"id": identifier, "type": "responseEnvelope", "phase": "response",
        "statusCodes": list(STATUSES), "contentTypePolicy": CONTENT_TYPE_POLICY,
        "bodyPresence": "required", "contentTypes": list(CONTENT_TYPES),
        "allowedResponseHeaderNames": [], "responseHeaderRules": [],
        "unlistedHeaderPolicy": "discardUnselectedV1"}


def validate_response_profile(response, constraints=None):
    _need(response == response_profile() and type(response["maxBodyBytes"]) is int
        and type(response["error"]["maxBodyBytes"]) is int)
    if constraints is not None:
        _need(len(constraints) == 1 and isinstance(constraints[0], dict)
            and type(constraints[0].get("id")) is str and bool(constraints[0]["id"])
            and constraints[0] == response_envelope(constraints[0]["id"])
            and all(type(status) is int for status in constraints[0]["statusCodes"]))


def validate_config(config):
    _need(isinstance(config, dict) and set(config) == {"credentialBinding", "registryId", "region",
        "repositoryName", "imageTag", "approval", "request", "response"})
    validate_scope(config["registryId"], config["region"], config["repositoryName"], config["imageTag"])
    binding = config["credentialBinding"]
    _need(isinstance(binding, dict) and set(binding) == {"credentialType", "provider", "subjects", "secretClass"}
        and binding["credentialType"] == "static" and binding["provider"] == "operator-demo"
        and binding["secretClass"] == "awsSigV4" and isinstance(binding["subjects"], list)
        and len(binding["subjects"]) == 1 and type(binding["subjects"][0]) is str
        and str(UUID(binding["subjects"][0])) == binding["subjects"][0]
        and config["approval"] == APPROVAL and config["request"] == request_profile()
        and type(config["request"]["maxBodyBytes"]) is int)
    validate_response_profile(config["response"])


def validate_authority(config, *, adapter, host: str, credential_ref, jit, methods, paths, constraints):
    validate_config(config)
    _need(adapter == ADAPTER and host == "api.ecr." + config["region"] + ".amazonaws.com"
        and bool(credential_ref) and not jit and methods == frozenset({"POST"}) and tuple(paths) == ("/",))
    validate_response_profile(config["response"], constraints)


def validate_route(route):
    _need(route.scheme == "https" and type(route.port) is int and route.port == 443
        and route.credential_header is None)
    validate_authority(route.adapter_config, adapter=route.adapter_type, host=route.host,
        credential_ref=route.credential_ref, jit=route.jit, methods=route.methods,
        paths=route.path_templates, constraints=route.constraints)
