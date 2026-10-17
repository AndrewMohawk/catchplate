"""Closed, byte-preserving npm publish authority; no archive inspection or fetching.

This profile is independent of the legacy npm.registry adapter. The tarball URL
inside the manifest is inert npm metadata, never an outbound request target.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re

from catchplate import npm_metadata
from catchplate.host_trusted_approval_policy import provider_constraints

ADAPTER = "npm.publish.v1"
MODE = "npmPublishJsonV1"
CONTENT_TYPE_POLICY = npm_metadata.CONTENT_TYPE_POLICY
ORIGIN = npm_metadata.ORIGIN
HOST = npm_metadata.HOST
OPERATION = "npm.publish"
PLACEHOLDER = npm_metadata.PLACEHOLDER
REPLACEMENT = dict(npm_metadata.REPLACEMENT)
PATHS = list(npm_metadata.PATHS)
MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024
MAX_TARBALL_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BUDGET = 65536
REQUEST_HEADERS = ["accept", "content-type", "npm-auth-type", "npm-command",
    "npm-in-ci", "npm-scope", "user-agent"]
STATUSES = [200, 201, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503, 504]
CONTENT_TYPES = ["application/json"]
OPERATION_FIELDS = frozenset({"operation", "packageName", "packageVersion", "tag",
    "tarballIntegrity", "tarballShasum", "attachmentName", "attachmentBytes"})
TAG_PATTERN = r"[a-z][a-z0-9._-]{0,63}"
_TAG = re.compile(TAG_PATTERN + r"\Z")
_NUMBER = r"(?:0|[1-9][0-9]*)"
_PRERELEASE = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_VERSION = re.compile(_NUMBER + r"\." + _NUMBER + r"\." + _NUMBER
    + r"(?:-" + _PRERELEASE + r"(?:\." + _PRERELEASE + r")*)?"
    + r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z")
_CLOCK = re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]\Z")


def _require(condition):
    if not condition:
        raise ValueError("npm publish contract refused")


def validate_package(package):
    npm_metadata.validate_packages([package])
    return package


def validate_tag(tag):
    _require(isinstance(tag, str) and _TAG.fullmatch(tag) is not None)
    return tag


def validate_version(version):
    _require(isinstance(version, str) and 1 <= len(version) <= 128
        and _VERSION.fullmatch(version) is not None)
    return version


def validate_window(window):
    if window is None:
        return None
    _require(isinstance(window, dict) and set(window) == {"timezone", "start", "end"}
        and window["timezone"] == "UTC"
        and all(isinstance(window[key], str) and _CLOCK.fullmatch(window[key])
            for key in ("start", "end")) and window["start"] < window["end"])
    return dict(window)


def time_window_constraint(identifier, window):
    window = validate_window(window)
    _require(isinstance(identifier, str) and bool(identifier) and window is not None)
    return {"id": identifier, "type": "requestTimeWindow", "phase": "request",
        "timezone": "UTC", "dailyWindows": [{"start": window["start"], "end": window["end"]}]}


def request_profile():
    return {"allowedHeaders": list(REQUEST_HEADERS),
        "discardHeaders": ["accept-encoding", "npm-session"], "allowedQueryKeys": [],
        "allowedMediaTypes": ["application/json"], "maxBodyBytes": MAX_REQUEST_BODY_BYTES,
        "valueRules": []}


def response_profile():
    return {"mode": MODE, "maxBodyBytes": 65536, "contentTypes": list(CONTENT_TYPES),
        "allowedHeaders": [], "error": {"mode": MODE, "maxBodyBytes": 65536,
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
    if constraints is None:
        return
    constraints = provider_constraints(constraints)
    _require(1 <= len(constraints) <= 2 and all(isinstance(item, dict) for item in constraints))
    envelopes = [item for item in constraints if item.get("type") == "responseEnvelope"]
    windows = [item for item in constraints if item.get("type") == "requestTimeWindow"]
    _require(len(envelopes) == 1 and len(envelopes) + len(windows) == len(constraints)
        and len(windows) <= 1)
    envelope = envelopes[0]
    _require(isinstance(envelope.get("id"), str) and bool(envelope["id"])
        and envelope == response_envelope(envelope["id"])
        and all(type(status) is int for status in envelope["statusCodes"]))
    if windows:
        item = windows[0]
        daily = item.get("dailyWindows")
        _require(isinstance(daily, list) and len(daily) == 1 and isinstance(daily[0], dict)
            and set(daily[0]) == {"start", "end"})
        expected = time_window_constraint(item.get("id"),
            {"timezone": item.get("timezone"), **daily[0]})
        _require(item == expected and item["id"] != envelope["id"])


def validate_config(config):
    _require(isinstance(config, dict)
        and set(config) == {"credentialBinding", "package", "tag", "request", "response"})
    validate_package(config["package"])
    validate_tag(config["tag"])
    # Reuse precisely the existing static operator bearer binding, without
    # broadening legacy registry credential providers or secret classes.
    npm_metadata.validate_config({"credentialBinding": config["credentialBinding"],
        "packages": [config["package"]], "request": npm_metadata.request_profile(),
        "response": npm_metadata.response_profile()})
    _require(config["request"] == request_profile()
        and type(config["request"]["maxBodyBytes"]) is int)
    validate_response_profile(config["response"])


def validate_authority(config, *, adapter, host, credential_ref, jit, methods, paths, constraints):
    validate_config(config)
    _require(adapter == ADAPTER and host == HOST and bool(credential_ref) and not jit
        and methods == frozenset({"PUT"}) and tuple(paths) == tuple(PATHS))
    validate_response_profile(config["response"], constraints)


def validate_route(route):
    _require(route.scheme == "https" and type(route.port) is int and route.port == 443
        and route.credential_header == REPLACEMENT)
    validate_authority(route.adapter_config, adapter=route.adapter_type, host=route.host,
        credential_ref=route.credential_ref, jit=route.jit, methods=route.methods,
        paths=route.path_templates, constraints=route.constraints)


def target_parts(url):
    return npm_metadata.target_parts(url)


def package_from_path(path):
    return npm_metadata.package_from_path(path)


def _document(body):
    # Local import avoids a module cycle: the compiler imports our pure profile
    # helpers, while request parsing reuses its existing duplicate/number rules.
    from catchplate.policy_bundle import strict_json_loads

    _require(isinstance(body, bytes) and 1 <= len(body) <= MAX_REQUEST_BODY_BYTES)
    try:
        value = strict_json_loads(body)
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ValueError("npm publish contract refused") from None
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        _require(depth <= 64 and count <= 100000)
        if isinstance(item, str):
            item.encode("utf-8")  # Reject escaped unpaired surrogates too.
        elif isinstance(item, dict):
            pending.extend((child, depth + 1) for pair in item.items() for child in pair)
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def manifest_budget(value):
    """Conservative cross-language bound, independent of numeric spellings.

    JSON punctuation/strings/literals use their compact UTF-8 byte counts. Each
    finite number costs 320 bytes, including numbers parsed as integers. This
    inspects metadata only and never serializes replacement request bytes.
    """
    pending = [(value, 0)]
    total = 0
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        _require(depth <= 64 and count <= 100000)
        if item is None:
            total += 4
        elif type(item) is bool:
            total += 4 if item else 5
        elif isinstance(item, (int, float)):
            try:
                _require(math.isfinite(float(item)))
            except OverflowError:
                raise ValueError("npm publish contract refused") from None
            total += 320
        elif isinstance(item, str):
            total += len(json.dumps(item, ensure_ascii=False).encode("utf-8"))
        elif isinstance(item, list):
            total += 2 + max(0, len(item) - 1)
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, dict):
            _require(all(isinstance(key, str) for key in item))
            total += 2 + max(0, len(item) - 1) + len(item)
            pending.extend((child, depth + 1) for pair in item.items() for child in pair)
        else:
            raise ValueError("npm publish contract refused")
    return total


def validate_request(method, url, body, *, package, tag):
    validate_package(package)
    validate_tag(tag)
    _require(method == "PUT" and package_from_path(target_parts(url).path) == package)
    document = _document(body)
    required = {"_id", "name", "dist-tags", "versions", "access", "_attachments"}
    _require(isinstance(document, dict) and required <= set(document)
        and set(document) <= required | {"description"}
        and document["_id"] == package and document["name"] == package
        and (document["access"] is None or document["access"] in ("public", "restricted"))
        and ("description" not in document or isinstance(document["description"], str)))
    versions = document["versions"]
    _require(isinstance(versions, dict) and len(versions) == 1)
    version = validate_version(next(iter(versions)))
    manifest = versions[version]
    _require(document["dist-tags"] == {tag: version}
        and isinstance(manifest, dict) and manifest.get("name") == package
        and manifest.get("version") == version and manifest.get("_id") == package + "@" + version)
    _require(manifest_budget(manifest) <= MAX_MANIFEST_BUDGET)
    name = package + "-" + version + ".tgz"
    attachments = document["_attachments"]
    _require(isinstance(attachments, dict) and set(attachments) == {name})
    attachment = attachments[name]
    _require(isinstance(attachment, dict) and set(attachment) == {"content_type", "data", "length"}
        and attachment["content_type"] == "application/octet-stream"
        and type(attachment["length"]) is int and 1 <= attachment["length"] <= MAX_TARBALL_BYTES
        and isinstance(attachment["data"], str)
        and 1 <= len(attachment["data"]) <= ((MAX_TARBALL_BYTES + 2) // 3) * 4)
    encoded = attachment["data"]
    # Check decoded size from padding before allocating the decoded attachment.
    _require(encoded.isascii() and len(encoded) % 4 == 0)
    padding = len(encoded) - len(encoded.rstrip("="))
    _require(padding <= 2 and 1 <= len(encoded) // 4 * 3 - padding <= MAX_TARBALL_BYTES)
    tarball = base64.b64decode(encoded, validate=True)
    _require(len(tarball) == attachment["length"] and base64.b64encode(tarball).decode("ascii") == encoded)
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode("ascii")
    shasum = hashlib.sha1(tarball, usedforsecurity=False).hexdigest()
    dist = manifest.get("dist")
    _require(isinstance(dist, dict) and set(dist) == {"integrity", "shasum", "tarball"}
        and dist["integrity"] == integrity and dist["shasum"] == shasum
        and dist["tarball"] == "http://" + HOST + "/" + package + "/-/" + name)
    return {"operation": OPERATION, "packageName": package, "packageVersion": version,
        "tag": tag, "tarballIntegrity": integrity, "tarballShasum": shasum,
        "attachmentName": name, "attachmentBytes": str(len(tarball))}


def is_json_content_type(value):
    return (isinstance(value, str) and value.isascii() and 0 < len(value) <= 8192
        and re.fullmatch(r"application/json(?:;[ \t]*charset=utf-8)?", value, re.I) is not None)
