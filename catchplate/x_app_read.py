"""Closed app-only X username lookup, independent of custody and transport.

This is not the legacy X OAuth adapter. The saved username, static credential
binding and exact public placeholder are authority, not caller-selected hints.
An accepted provider JSON object is not proof of account ownership or lookup
success. No request or response body is rewritten by this profile.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from catchplate.host_trusted_approval_policy import provider_constraints

ADAPTER = "x.app_read.v1"
MODE = "xAppReadJsonV1"
CONTENT_TYPE_POLICY = "xAppReadJsonUtf8V1"
HOST = "api.x.com"
ORIGIN = "https://" + HOST
OPERATION = "x.username.read"
OPERATION_FIELDS = frozenset({"operation", "username"})
PLACEHOLDER = "catchplate-x-placeholder-v1"
REPLACEMENT = {"mode": "replaceExact", "expectedValue": "Bearer " + PLACEHOLDER}
USERNAME_PATTERN = r"[a-z0-9_]{1,15}"
REQUEST_HEADERS = ["accept", "accept-language", "sec-fetch-mode", "user-agent"]
CONTENT_TYPES = ["application/json"]
STATUSES = [200, 400, 401, 403, 404, 429, 500, 502, 503, 504]
MAX_RESPONSE_BYTES = 1048576
MAX_ERROR_BYTES = 65536


def _require(condition):
    if not condition:
        raise ValueError("X app read contract refused")


def validate_username(value):
    _require(isinstance(value, str) and re.fullmatch(USERNAME_PATTERN, value) is not None)
    return value


def validate_token(value):
    # Provider tokens are opaque: no guessed prefix, percent-decoding or OAuth
    # identity is derived here. Syntax validation does not test entitlement.
    _require(isinstance(value, str) and 1 <= len(value) <= 8192
        and all(33 <= ord(character) <= 126 for character in value))
    return value


def route_paths(username):
    return ["/2/users/by/username/" + validate_username(username)]


def request_profile():
    return {"allowedHeaders": list(REQUEST_HEADERS), "discardHeaders": ["accept-encoding"],
        "allowedQueryKeys": [], "allowedMediaTypes": list(CONTENT_TYPES),
        "maxBodyBytes": 0, "valueRules": []}


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


def validate_response_profile(response, constraints=None):
    _require(response == response_profile() and type(response["maxBodyBytes"]) is int
        and type(response["error"]["maxBodyBytes"]) is int)
    if constraints is not None:
        constraints = provider_constraints(constraints)
        _require(len(constraints) == 1 and isinstance(constraints[0], dict)
            and isinstance(constraints[0].get("id"), str) and bool(constraints[0]["id"])
            and constraints[0] == response_envelope(constraints[0]["id"])
            and all(type(status) is int for status in constraints[0]["statusCodes"]))


def validate_config(config):
    _require(isinstance(config, dict)
        and set(config) == {"credentialBinding", "username", "request", "response"})
    validate_username(config["username"])
    binding = config["credentialBinding"]
    _require(isinstance(binding, dict)
        and set(binding) == {"credentialType", "provider", "subjects", "secretClass"}
        and binding["credentialType"] == "static" and binding["provider"] == "operator-demo"
        and binding["secretClass"] == "bearerToken" and isinstance(binding["subjects"], list)
        and len(binding["subjects"]) == 1 and isinstance(binding["subjects"][0], str)
        and 1 <= len(binding["subjects"][0].encode("utf-8")) <= 512
        and binding["subjects"][0].strip() == binding["subjects"][0]
        and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in binding["subjects"][0])
        and config["request"] == request_profile()
        and type(config["request"]["maxBodyBytes"]) is int)
    validate_response_profile(config["response"])


def validate_authority(config, *, adapter, host, credential_ref, jit, methods, paths, constraints):
    validate_config(config)
    _require(adapter == ADAPTER and host == HOST and bool(credential_ref) and not jit
        and methods == frozenset({"GET"}) and tuple(paths) == tuple(route_paths(config["username"])))
    validate_response_profile(config["response"], constraints)


def validate_route(route):
    _require(route.scheme == "https" and type(route.port) is int and route.port == 443
        and route.credential_header == REPLACEMENT)
    validate_authority(route.adapter_config, adapter=route.adapter_type, host=route.host,
        credential_ref=route.credential_ref, jit=route.jit, methods=route.methods,
        paths=route.path_templates, constraints=route.constraints)


def target_parts(url):
    _require(isinstance(url, str) and re.fullmatch(
        re.escape(ORIGIN) + r"/2/users/by/username/(" + USERNAME_PATTERN + r")", url) is not None)
    return urlsplit(url)


def is_json_content_type(value):
    return (isinstance(value, str) and value.isascii() and 0 < len(value) <= 8192
        and re.fullmatch(r"application/json(?:;[ \t]*charset=utf-8)?", value, re.I) is not None)


def validate_request(method, url, body, *, username, headers=None):
    validate_username(username)
    _require(method == "GET" and isinstance(body, bytes) and body == b""
        and target_parts(url).path == route_paths(username)[0])
    # The adapter supplies singleton normalized fields after the common framing
    # and authentication admission. This pure check does not authorize a token.
    if headers is not None:
        _require(isinstance(headers, dict))
        if "content-type" in headers:
            _require(is_json_content_type(headers["content-type"]))
        if "accept" in headers:
            _require(headers["accept"] in {"application/json", "*/*"})
        for name, expected in (("accept-language", "*"), ("sec-fetch-mode", "cors")):
            _require(name not in headers or headers[name] == expected)
    return username
