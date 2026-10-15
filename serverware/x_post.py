"""Closed, byte-preserving X text posting contract, not OAuth enrollment.

Only the signed OAuth account/client and fixed text-only endpoint are selected.
Provider JSON is retained whole; admission does not prove posting success. The
optional shared-account quota is a policy contract, not a local-store fallback.
This module performs no network, storage, credential acquisition or retries.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from serverware.host_trusted_approval_policy import provider_constraints

ADAPTER = "x.post.v1"
MODE = "xPostJsonV1"
CONTENT_TYPE_POLICY = "xPostJsonUtf8V1"
HOST = "api.x.com"
ORIGIN = "https://" + HOST
PATH = "/2/tweets"
OPERATION = "tweets.write"
OPERATION_FIELDS = frozenset({"operation"})
PLACEHOLDER = "serverware-x-post-placeholder-v1"
REPLACEMENT = {"mode": "replaceExact", "expectedValue": "Bearer " + PLACEHOLDER}
REQUIRED_SCOPES = ["offline.access", "tweet.read", "tweet.write", "users.read"]
REQUEST_HEADERS = ["accept", "accept-language", "content-type", "sec-fetch-mode", "user-agent"]
CONTENT_TYPES = ["application/json"]
STATUSES = [201, 400, 401, 402, 403, 404, 408, 409, 422, 429, 500, 502, 503, 504]
MAX_REQUEST_BODY_BYTES = 32768
MAX_TEXT_BYTES = 16384
MAX_RESPONSE_BYTES = 1048576
MAX_ERROR_BYTES = 65536
QUOTA_ID = "x-post-account-utc-day-v1"


def _require(condition):
    if not condition:
        raise ValueError("X post contract refused")


def route_paths():
    return [PATH]


def request_profile():
    return {"allowedHeaders": list(REQUEST_HEADERS), "discardHeaders": ["accept-encoding"],
        "allowedQueryKeys": [], "allowedMediaTypes": list(CONTENT_TYPES),
        "maxBodyBytes": MAX_REQUEST_BODY_BYTES, "valueRules": []}


def response_profile():
    return {"mode": MODE, "maxBodyBytes": MAX_RESPONSE_BYTES,
        "contentTypes": list(CONTENT_TYPES), "allowedHeaders": [],
        "error": {"mode": MODE, "maxBodyBytes": MAX_ERROR_BYTES,
            "contentTypes": list(CONTENT_TYPES), "allowedHeaders": [], "onInvalid": "block"}}


def response_envelope(identifier):
    return {"id": identifier, "type": "responseEnvelope", "phase": "response",
        "statusCodes": list(STATUSES), "bodyPresence": "required",
        "contentTypes": list(CONTENT_TYPES), "allowedResponseHeaderNames": [],
        "responseHeaderRules": [], "unlistedHeaderPolicy": "discardUnselectedV1",
        "contentTypePolicy": CONTENT_TYPE_POLICY}


def quota_constraint(maximum):
    _require(type(maximum) is int and 1 <= maximum <= 1000000000)
    return {"id": QUOTA_ID, "type": "rateLimit", "max": maximum,
        "calendarWindow": "utcDay", "windowSemantics": "calendarUTC", "store": "shared",
        "key": {"scope": ["operation"], "operationFields": ["providerAccount"]}}


def validate_response_profile(response, constraints=None):
    _require(response == response_profile() and type(response["maxBodyBytes"]) is int
        and type(response["error"]["maxBodyBytes"]) is int)
    if constraints is None:
        return
    rows = provider_constraints(constraints)
    _require(1 <= len(rows) <= 2 and all(isinstance(row, dict) for row in rows))
    envelopes = [row for row in rows if row.get("type") == "responseEnvelope"]
    _require(len(envelopes) == 1)
    envelope = envelopes[0]
    _require(isinstance(envelope.get("id"), str) and bool(envelope["id"])
        and envelope["id"] != QUOTA_ID
        and envelope == response_envelope(envelope["id"])
        and all(type(status) is int for status in envelope["statusCodes"]))
    for row in rows:
        if row is not envelope:
            _require(row == quota_constraint(row.get("max")) and envelope["id"] != QUOTA_ID)


def _identity(value):
    try:
        _require(isinstance(value, str) and 1 <= len(value.encode("utf-8")) <= 512
            and value.strip() == value
            and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value))
    except UnicodeError:
        raise ValueError("X post contract refused") from None


def validate_config(config):
    _require(isinstance(config, dict) and set(config) == {"credentialBinding", "request", "response"})
    binding = config["credentialBinding"]
    _require(isinstance(binding, dict)
        and set(binding) == {"credentialType", "provider", "subjects", "clientIds", "requiredScopes"}
        and binding["credentialType"] == "oauth2" and binding["provider"] == "x"
        and binding["requiredScopes"] == REQUIRED_SCOPES)
    for field in ("subjects", "clientIds"):
        _require(isinstance(binding[field], list) and len(binding[field]) == 1)
        _identity(binding[field][0])
    _require(config["request"] == request_profile() and type(config["request"]["maxBodyBytes"]) is int)
    validate_response_profile(config["response"])


def validate_authority(config, *, adapter, host, credential_ref, jit, methods, paths, constraints):
    validate_config(config)
    _require(adapter == ADAPTER and host == HOST and bool(credential_ref) and not jit
        and methods == frozenset({"POST"}) and tuple(paths) == (PATH,))
    validate_response_profile(config["response"], constraints)


def validate_route(route):
    _require(route.scheme == "https" and type(route.port) is int and route.port == 443
        and route.credential_header == REPLACEMENT)
    validate_authority(route.adapter_config, adapter=route.adapter_type, host=route.host,
        credential_ref=route.credential_ref, jit=route.jit, methods=route.methods,
        paths=route.path_templates, constraints=route.constraints)


def validate_policy_routes(routes, credentials):
    """After per-route binding validation, forbid account quota split/bypass.

    Credential IDs, OAuth clients and route IDs do not partition this quota.
    Credentials are the actual compiler's validated CredentialPolicy objects.
    """
    from serverware.policy_bundle import _path_template_to_regex
    quotas = {}
    for route in routes:
        if route["adapter"]["type"] != ADAPTER:
            continue
        config, constraints = route["adapter"]["config"], route.get("constraints", [])
        validate_response_profile(config["response"], constraints)
        credential = credentials[route["credentialRef"]]
        _require(credential.kind == "oauth2" and credential.provider == "x"
            and config["credentialBinding"]["subjects"] == [credential.provider_subject])
        key = credential.provider_subject
        quota = next((row["max"] for row in constraints if row["type"] == "rateLimit"), None)
        _require(key not in quotas or quotas[key] == quota)
        quotas[key] = quota
    limited = {subject for subject, maximum in quotas.items() if maximum is not None}
    for route in routes:
        credential = credentials.get(route.get("credentialRef"))
        if credential is None or credential.provider != "x" or credential.provider_subject not in limited:
            continue
        adapter, match = route["adapter"], route["match"]
        legacy_write = adapter["type"] == "x.v2" and adapter["config"].get("mode") == "controlledWrite"
        generic_overlap = (adapter["type"] == "generic.rest" and match.get("scheme", "https") == "https"
            and match["host"] == HOST and match.get("port", 443) == 443 and "POST" in match["methods"]
            and any(_path_template_to_regex(path).fullmatch(PATH) for path in match["paths"]))
        _require(not legacy_write and not generic_overlap)


def target_parts(url):
    _require(isinstance(url, str) and url == ORIGIN + PATH)
    return urlsplit(url)


def is_json_content_type(value):
    return (isinstance(value, str) and value.isascii() and 0 < len(value) <= 8192
        and re.fullmatch(r"application/json(?:;[ \t]*charset=utf-8)?", value, re.I) is not None)


def validate_request(method, url, body, *, headers=None):
    from serverware.policy_bundle import strict_json_loads
    _require(method == "POST" and target_parts(url).path == PATH
        and isinstance(body, bytes) and 1 <= len(body) <= MAX_REQUEST_BODY_BYTES)
    try:
        document = strict_json_loads(body)
        _require(isinstance(document, dict) and set(document) == {"text"}
            and isinstance(document["text"], str) and "\x00" not in document["text"]
            and 1 <= len(document["text"].encode("utf-8")) <= MAX_TEXT_BYTES)
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ValueError("X post contract refused") from None
    if headers is not None:
        _require(isinstance(headers, dict) and is_json_content_type(headers.get("content-type")))
        if "accept" in headers:
            _require(headers["accept"] in {"application/json", "*/*"})
        for name, expected in (("accept-language", "*"), ("sec-fetch-mode", "cors")):
            _require(name not in headers or headers[name] == expected)
    return {"operation": OPERATION}
