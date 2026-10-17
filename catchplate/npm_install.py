"""Closed npm installation reads, independent of credential or transport authority.

The signed package closure governs every request separately. Packument URLs
never create grants. Gzip inspection does not extract or assert archive safety;
original compressed bytes remain the request/response commitment and payload.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit
import zlib

from catchplate import npm_metadata, npm_publish
from catchplate.host_trusted_approval_policy import provider_constraints

ADAPTER = "npm.install.v1"
MODES = ("metadata", "tarball", "audit")
RESPONSE_MODES = {"metadata": "npmInstallMetadataJsonV1", "tarball": "npmInstallTarballV1",
    "audit": "npmInstallAuditJsonV1"}
CONTENT_TYPE_POLICY = "npmInstallContentV1"
ORIGIN, HOST = npm_metadata.ORIGIN, npm_metadata.HOST
PLACEHOLDER, REPLACEMENT = npm_metadata.PLACEHOLDER, dict(npm_metadata.REPLACEMENT)
STATUSES = list(npm_metadata.STATUSES)
OPERATIONS = {mode: "npm.install." + mode + ".read" for mode in MODES}
OPERATION_FIELDS = {OPERATIONS["metadata"]: frozenset({"operation", "package"}),
    OPERATIONS["tarball"]: frozenset({"operation", "package", "version"}),
    OPERATIONS["audit"]: frozenset({"operation", "packages", "packageVersions"})}
MAX_JSON_BYTES = 1048576
MAX_ERROR_BYTES = 65536
MAX_TARBALL_BYTES = 8 * 1024 * 1024
MAX_TARBALL_DECODED_BYTES = 32 * 1024 * 1024
MAX_AUDIT_BYTES = 65536
MAX_AUDIT_DECODED_BYTES = 262144
AUDIT_PATH = "/-/npm/v1/security/advisories/bulk"
REQUEST_HEADERS = {
    "metadata": list(npm_metadata.REQUEST_HEADERS),
    "tarball": sorted([*npm_metadata.REQUEST_HEADERS, "pacote-integrity"]),
    "audit": ["accept", "content-type", "npm-auth-type", "npm-command", "npm-in-ci", "npm-scope", "user-agent"],
}
validate_packages = npm_metadata.validate_packages


def _require(value):
    if not value:
        raise ValueError("npm install contract refused")


def _mode(mode):
    _require(type(mode) is str and mode in MODES)
    return mode


def route_paths(mode):
    return {"metadata": ["/{package}"], "tarball": ["/{package}/-/{filename}",
        "/{scope}/{package}/-/{filename}"], "audit": [AUDIT_PATH]}[_mode(mode)]


def request_profile(mode):
    mode = _mode(mode)
    return {"allowedHeaders": list(REQUEST_HEADERS[mode]),
        "discardHeaders": ["accept-encoding", "npm-session"], "allowedQueryKeys": [],
        "allowedMediaTypes": ["application/json"] if mode == "audit" else [],
        "maxBodyBytes": MAX_AUDIT_BYTES if mode == "audit" else 0, "valueRules": []}


def response_content_types(mode, status=200):
    mode = _mode(mode)
    return (list(npm_metadata.CONTENT_TYPES) if mode == "metadata" else
        ["application/octet-stream"] if mode == "tarball" and status == 200 else ["application/json"])


def response_profile(mode):
    mode = _mode(mode)
    return {"mode": RESPONSE_MODES[mode], "maxBodyBytes": MAX_TARBALL_BYTES if mode == "tarball" else MAX_JSON_BYTES,
        "contentTypes": response_content_types(mode), "allowedHeaders": [],
        "error": {"mode": RESPONSE_MODES[mode], "maxBodyBytes": MAX_ERROR_BYTES,
            "contentTypes": response_content_types(mode, 400), "allowedHeaders": [], "onInvalid": "block"}}


def response_envelope(identifier, mode):
    mode = _mode(mode)
    return {"id": identifier, "type": "responseEnvelope", "phase": "response",
        "statusCodes": list(STATUSES), "bodyPresence": "required",
        "contentTypes": sorted(set(response_content_types(mode) + response_content_types(mode, 400))),
        "allowedResponseHeaderNames": [], "responseHeaderRules": [],
        "unlistedHeaderPolicy": "discardUnselectedV1", "contentTypePolicy": CONTENT_TYPE_POLICY}


def validate_response_profile(response, constraints=None, *, mode):
    _require(response == response_profile(mode) and type(response["maxBodyBytes"]) is int
        and type(response["error"]["maxBodyBytes"]) is int)
    if constraints is not None:
        rows = provider_constraints(constraints)
        _require(len(rows) == 1 and isinstance(rows[0], dict)
            and isinstance(rows[0].get("id"), str) and bool(rows[0]["id"])
            and rows[0] == response_envelope(rows[0]["id"], mode)
            and all(type(status) is int for status in rows[0]["statusCodes"]))


def validate_config(config):
    _require(isinstance(config, dict) and set(config) == {"credentialBinding", "packages", "mode", "request", "response"})
    mode = _mode(config["mode"])
    npm_metadata.validate_config({"credentialBinding": config["credentialBinding"], "packages": config["packages"],
        "request": npm_metadata.request_profile(), "response": npm_metadata.response_profile()})
    _require(config["request"] == request_profile(mode) and type(config["request"]["maxBodyBytes"]) is int)
    validate_response_profile(config["response"], mode=mode)


def validate_authority(config, *, adapter, host, credential_ref, jit, methods, paths, constraints):
    validate_config(config)
    mode = config["mode"]
    _require(adapter == ADAPTER and host == HOST and bool(credential_ref) and not jit
        and methods == frozenset({"POST" if mode == "audit" else "GET"})
        and tuple(paths) == tuple(route_paths(mode)))
    validate_response_profile(config["response"], constraints, mode=mode)


def validate_route(route):
    _require(route.scheme == "https" and type(route.port) is int and route.port == 443
        and route.credential_header == REPLACEMENT)
    validate_authority(route.adapter_config, adapter=route.adapter_type, host=route.host,
        credential_ref=route.credential_ref, jit=route.jit, methods=route.methods,
        paths=route.path_templates, constraints=route.constraints)


def tarball_from_path(path):
    _require(type(path) is str and path.startswith("/") and len(path) <= 512 and "%" not in path)
    components = path[1:].split("/")
    if len(components) == 3:
        package, separator, filename = components
        _require(not package.startswith("@"))
    else:
        _require(len(components) == 4 and components[0].startswith("@"))
        scope, name, separator, filename = components
        package = scope + "/" + name
    validate_packages([package])
    prefix = package.rsplit("/", 1)[-1] + "-"
    _require(separator == "-" and filename.startswith(prefix) and filename.endswith(".tgz"))
    version = filename[len(prefix):-4]
    npm_publish.validate_version(version)
    return package, version


def target_parts(url, mode):
    mode = _mode(mode)
    _require(type(url) is str and url.isascii() and len(url) <= 1024 and "?" not in url and "#" not in url
        and all(33 <= ord(char) <= 126 and char != "\\" for char in url))
    parts = urlsplit(url)
    _require(parts.scheme == "https" and parts.netloc == HOST and url == ORIGIN + parts.path)
    if mode == "metadata":
        npm_metadata.package_from_path(parts.path)
    elif mode == "tarball":
        tarball_from_path(parts.path)
    else:
        _require(parts.path == AUDIT_PATH)
    return parts


def bounded_gzip(raw, compressed_limit, decoded_limit):
    """Inspect one complete gzip member; reject concatenation and trailing bytes."""
    _require(type(raw) is bytes and 1 <= len(raw) <= compressed_limit)
    decoded = bytearray()
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decoded.extend(decoder.decompress(raw, decoded_limit + 1))
        _require(1 <= len(decoded) <= decoded_limit and decoder.eof
            and not decoder.unused_data and not decoder.unconsumed_tail)
        return decoded
    except (ValueError, zlib.error):
        decoded[:] = b"\x00" * len(decoded)
        raise ValueError("npm install gzip refused") from None


def _audit_versions(body, packages):
    from catchplate.policy_bundle import strict_json_loads

    decoded = bounded_gzip(body, MAX_AUDIT_BYTES, MAX_AUDIT_DECODED_BYTES)
    try:
        # The admitted shape is only object -> arrays -> strings. Reject deeper
        # input before invoking the JSON decoder; escaped brackets are inert.
        depth, in_string, escaped = 0, False, False
        for byte in decoded:
            if in_string:
                if escaped:
                    escaped = False
                elif byte == 92:
                    escaped = True
                elif byte == 34:
                    in_string = False
            elif byte == 34:
                in_string = True
            elif byte in (91, 123):
                depth += 1
                _require(depth <= 64)
            elif byte in (93, 125):
                depth -= 1
                _require(depth >= 0)
        value = strict_json_loads(decoded)
        _require(isinstance(value, dict) and 1 <= len(value) <= 64 and set(value) <= set(packages))
        out = {}
        for package in sorted(value):
            validate_packages([package])
            versions = value[package]
            _require(isinstance(versions, list) and 1 <= len(versions) <= 128
                and all(type(version) is str for version in versions) and len(set(versions)) == len(versions))
            out[package] = sorted(npm_publish.validate_version(version) for version in versions)
        return out
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise ValueError("npm install audit refused") from None
    finally:
        decoded[:] = b"\x00" * len(decoded)


def is_content_type(mode, status, value):
    _mode(mode)
    if mode == "metadata":
        return npm_metadata.is_json_content_type(value)
    if mode == "tarball" and status == 200:
        return type(value) is str and value.lower() == "application/octet-stream"
    return (type(value) is str and value.isascii() and len(value) <= 8192
        and re.fullmatch(r"application/json(?:;[ \t]*charset=utf-8)?", value, re.I) is not None)


def validate_request(method, url, body, *, packages, mode, headers):
    validate_packages(packages)
    mode = _mode(mode)
    path = target_parts(url, mode).path
    _require(type(body) is bytes and isinstance(headers, dict))
    if mode != "audit":
        _require(method == "GET" and body == b"" and "content-type" not in headers
            and "transfer-encoding" not in headers
            and headers.get("content-encoding") in {None, "identity"})
        package, version = ((npm_metadata.package_from_path(path), None) if mode == "metadata" else tarball_from_path(path))
        _require(package in packages)
        return {"operation": OPERATIONS[mode], "package": package, **({"version": version} if version is not None else {})}
    _require(method == "POST" and headers.get("content-encoding") == "gzip"
        and headers.get("content-length") == str(len(body)) and "transfer-encoding" not in headers
        and is_content_type("audit", 200, headers.get("content-type")))
    versions = _audit_versions(body, packages)
    return {"operation": OPERATIONS[mode], "packages": sorted(versions), "packageVersions": versions}


def validate_response(value, *, mode, status, operation):
    mode = _mode(mode)
    _require(isinstance(operation, dict) and operation.get("operation") == OPERATIONS[mode]
        and set(operation) == OPERATION_FIELDS[OPERATIONS[mode]])
    _require(type(status) is int and status in STATUSES and isinstance(value, dict))
    if status != 200:
        return
    if mode == "metadata":
        _require(value.get("name") == operation["package"])
    elif mode == "audit":
        _require(set(value) <= set(operation["packages"]) and all(isinstance(items, list)
            and all(isinstance(item, dict) for item in items) for items in value.values()))
    else:
        _require(False)  # Tarball success is binary, never this JSON path.
