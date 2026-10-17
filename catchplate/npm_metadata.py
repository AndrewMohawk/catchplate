"""Closed npm package-metadata authority, independent of custody and transport.

This profile does not authorize installation, tarballs, audit, or registry
writes. Package names are signed configuration, not caller-provided grants.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from catchplate.host_trusted_approval_policy import provider_constraints

ADAPTER = "npm.metadata.v1"
MODE = "npmMetadataJsonV1"
CONTENT_TYPE_POLICY = "npmJsonUtf8V1"
ORIGIN = "https://registry.npmjs.org"
HOST = "registry.npmjs.org"
OPERATION = "npm.metadata.read"
PLACEHOLDER = "catchplate-npm-placeholder-v1"
REPLACEMENT = {"mode": "replaceExact", "expectedValue": "Bearer " + PLACEHOLDER}
REQUEST_HEADERS = ["accept", "npm-auth-type", "npm-command", "npm-in-ci", "npm-scope",
    "pacote-pkg-id", "pacote-req-type", "pacote-version", "user-agent"]
STATUSES = [200, 400, 401, 403, 404, 429, 500, 502, 503, 504]
CONTENT_TYPES = ["application/json", "application/vnd.npm.install-v1+json"]
PATHS = ["/{package}"]
PACKAGE_PATTERN = r"(?:[a-z0-9][a-z0-9._-]*|@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*)"
_PACKAGE = re.compile(PACKAGE_PATTERN + r"\Z")


def _require(condition):
    if not condition:
        raise ValueError("npm metadata contract refused")


def validate_packages(packages):
    _require(isinstance(packages, list) and 1 <= len(packages) <= 64
        and all(isinstance(name, str) and 1 <= len(name) <= 214
            and _PACKAGE.fullmatch(name) is not None for name in packages)
        and packages == sorted(set(packages)))
    return list(packages)


def request_profile():
    return {"allowedHeaders": list(REQUEST_HEADERS),
        "discardHeaders": ["accept-encoding", "npm-session"], "allowedQueryKeys": [],
        "allowedMediaTypes": [], "maxBodyBytes": 0, "valueRules": []}


def response_profile():
    return {"mode": MODE, "maxBodyBytes": 1048576, "contentTypes": list(CONTENT_TYPES),
        "allowedHeaders": [], "error": {"mode": MODE, "maxBodyBytes": 65536,
            "contentTypes": list(CONTENT_TYPES), "allowedHeaders": [], "onInvalid": "block"}}


def response_envelope(identifier):
    return {"id": identifier, "type": "responseEnvelope", "phase": "response",
        "statusCodes": list(STATUSES), "bodyPresence": "required",
        "contentTypes": list(CONTENT_TYPES), "allowedResponseHeaderNames": [],
        "responseHeaderRules": [], "unlistedHeaderPolicy": "discardUnselectedV1",
        "contentTypePolicy": CONTENT_TYPE_POLICY}


def validate_response_profile(response, constraints=None):
    _require(response == response_profile()
        and type(response["maxBodyBytes"]) is int
        and type(response["error"]["maxBodyBytes"]) is int)
    if constraints is not None:
        constraints = provider_constraints(constraints)
        _require(len(constraints) == 1 and isinstance(constraints[0], dict)
            and isinstance(constraints[0].get("id"), str) and bool(constraints[0]["id"])
            and constraints[0] == response_envelope(constraints[0]["id"])
            and all(type(status) is int for status in constraints[0]["statusCodes"]))


def validate_config(config):
    _require(isinstance(config, dict)
        and set(config) == {"credentialBinding", "packages", "request", "response"})
    validate_packages(config["packages"])
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
        and methods == frozenset({"GET"}) and tuple(paths) == tuple(PATHS))
    validate_response_profile(config["response"], constraints)


def validate_route(route):
    _require(route.scheme == "https" and type(route.port) is int and route.port == 443
        and route.credential_header == REPLACEMENT)
    validate_authority(route.adapter_config, adapter=route.adapter_type, host=route.host,
        credential_ref=route.credential_ref, jit=route.jit, methods=route.methods,
        paths=route.path_templates, constraints=route.constraints)


def package_from_path(path):
    _require(isinstance(path, str) and path.startswith("/") and len(path) <= 217)
    encoded = path[1:]
    # Only one literal lowercase escaped slash is admitted, exclusively inside
    # the one scoped package capture. No general percent-decoding takes place.
    if encoded.startswith("@"):
        _require(encoded.count("%2f") == 1)
        package = encoded.replace("%2f", "/")
    else:
        package = encoded
    _require("/" not in encoded and "%" not in package
        and 1 <= len(package) <= 214 and _PACKAGE.fullmatch(package) is not None)
    return package


def target_parts(url):
    _require(isinstance(url, str) and url.isascii() and len(url) <= 512
        and "?" not in url and "#" not in url
        and not any(ord(char) < 33 or ord(char) > 126 or char == "\\" for char in url))
    parts = urlsplit(url)
    _require(parts.scheme == "https" and parts.netloc == HOST
        and url == "https://" + parts.netloc + parts.path)
    package_from_path(parts.path)
    return parts


def validate_request(method, url, body, *, packages):
    validate_packages(packages)
    _require(method == "GET" and isinstance(body, bytes) and body == b"")
    package = package_from_path(target_parts(url).path)
    _require(package in packages)
    return package


def is_json_content_type(value):
    return (isinstance(value, str) and value.isascii() and 0 < len(value) <= 8192
        and re.fullmatch(r"application/(?:json|vnd\.npm\.install-v1\+json)(?:;[ \t]*charset=utf-8)?", value, re.I) is not None)
