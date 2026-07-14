from __future__ import annotations

import copy
import base64
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware.config import (
    POLICY_BUNDLE_PATH,
    POLICY_MIN_ROLLBACK_EPOCH,
    POLICY_MIN_SEQUENCE,
    POLICY_SIGNING_KEY_PATH,
    POLICY_SIGNING_PUBLIC_KEY_PATH,
    SCHEMA_DIR,
    ensure_data_dirs,
)


SUPPORTED_ADAPTERS = {"generic.rest", "gmail.v1", "x.v2", "npm.registry"}
MANAGED_OAUTH_PROVIDERS = {
    "google",
    "google.oauth",
    "google.oauth2",
    "twitter",
    "x",
    "x.oauth",
    "x.oauth2",
}
X_V2_BOUNDED_READ_OPERATIONS = frozenset(
    {
        "accountActivity.read",
        "activity.read",
        "analytics.read",
        "bookmarks.read",
        "chat.read",
        "communities.read",
        "compliance.read",
        "connections.read",
        "directMessages.read",
        "insights.read",
        "lists.read",
        "media.read",
        "news.read",
        "notes.read",
        "schema.read",
        "search.read",
        "spaces.read",
        "trends.read",
        "tweets.read",
        "usage.read",
        "users.read",
        "webhooks.read",
    }
)
X_V2_RECENT_SEARCH_PATHS = frozenset(
    {
        "/2/tweets/counts/recent",
        "/2/tweets/search/recent",
    }
)
PROVIDER_ACCOUNT_OPERATION_FIELD = "providerAccount"
NPM_WRITE_OPERATIONS = frozenset(
    {"publish", "unpublish", "distTagWrite", "tokenWrite", "metadataWrite"}
)
SUPPORTED_CONSTRAINTS = {
    "rateLimit",
    "operationPolicy",
    "queryDateWindow",
    "queryNumericBounds",
    "requestTimeWindow",
    "jsonBody",
    "formBody",
    "responseDateWindow",
    "responseJson",
}
REQUEST_CONSTRAINTS = SUPPORTED_CONSTRAINTS - {"responseDateWindow", "responseJson"}
FAIL_CLOSED_DEFAULTS = {
    "action": "deny",
    "failMode": "closed",
    "unknownHosts": "block",
    "unknownPaths": "block",
    "validationFailure": "block",
}
REQUIRED_JIT_BINDING_FIELDS = {
    "principal",
    "routeId",
    "credentialRef",
    "credentialVersion",
    "policyHash",
    "method",
    "authority",
    "path",
    "query",
    "selectedHeaders",
    "bodySha256",
}
STREAMING_RESPONSE_MODES = {
    "stream",
    "jsonlStream",
    "jsonArrayStream",
    "jsonSseStream",
    "jsonNestedStream",
    "formUrlencodedStream",
    "csvStream",
}
BUFFERED_RESPONSE_MODES = {"any", "headersOnly", "json"}
SUPPORTED_RESPONSE_MODES = BUFFERED_RESPONSE_MODES | STREAMING_RESPONSE_MODES
FORBIDDEN_AGENT_CREDENTIAL_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
}
NON_FORWARDABLE_AGENT_HEADERS = FORBIDDEN_AGENT_CREDENTIAL_HEADERS | {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "x-serverware-agent",
    "x-serverware-admin-token",
    "x-serverware-audit-anchor-token",
    "x-serverware-ca-install-token",
    "x-serverware-csrf-token",
    "x-serverware-data-plane-token",
    "x-serverware-proof-nonce",
}
SAFE_RESPONSE_HEADERS = frozenset(
    {
        "cache-control",
        "content-language",
        "etag",
        "last-modified",
        "retry-after",
        "www-authenticate",
    }
)
MAX_PROVIDER_RESPONSE_BODY_BYTES = 1024 * 1024
MAX_PROVIDER_ERROR_BODY_BYTES = 64 * 1024
RESPONSE_FIELD_PATH_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$")
HTTP_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
CREDENTIAL_FIELD_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
CREDENTIAL_INJECTION_FIELDS = {
    "bearer": frozenset({"type", "header", "field", "prefix"}),
    "basic": frozenset({"type", "header", "field", "username"}),
    "header": frozenset({"type", "name", "field", "prefix"}),
    "query": frozenset({"type", "name", "field"}),
    "cookie": frozenset({"type", "name", "field"}),
}
REQUIRED_REQUEST_HEADER_RULE_FIELDS = {"type", "minLength", "maxLength", "pattern"}
FIELD_RULE_FIELDS = {
    "required",
    "type",
    "enum",
    "equals",
    "minLength",
    "maxLength",
    "pattern",
    "min",
    "max",
    "minItems",
    "maxItems",
}
FIELD_RULE_TYPES = {"string", "number", "integer", "boolean", "object", "array", "null"}
CONSTRAINT_COMMON_FIELDS = {"id", "description", "type", "phase", "statusCode", "extensions"}
CONSTRAINT_TYPE_FIELDS = {
    "rateLimit": {"store", "max", "windowSeconds", "key"},
    "operationPolicy": {"allowedOperations", "deniedOperations"},
    "queryDateWindow": {"parameters", "required", "formats", "maxAgeDays", "allowFutureSkewSeconds"},
    "queryNumericBounds": {"parameters", "required", "min", "max", "integer"},
    "requestTimeWindow": {"timezone", "notBefore", "notAfter", "weekdays", "dailyWindows"},
    "jsonBody": {"contentTypes", "allowedFields", "requiredFields", "deniedFields", "fields"},
    "formBody": {"contentTypes", "allowedFields", "requiredFields", "deniedFields", "fields"},
    "responseDateWindow": {
        "required",
        "formats",
        "maxAgeDays",
        "allowFutureSkewSeconds",
        "items",
        "dateFields",
        "operations",
    },
    "responseJson": {"required", "items", "fields", "operations"},
}


class PolicyBundleError(ValueError):
    pass


def provider_account_scope_value(provider: str, provider_subject: str | None) -> str | None:
    if not provider or not provider_subject:
        return None
    material = f"{provider}\0{provider_subject}".encode("utf-8")
    return "sha256:" + hashlib.sha256(material).hexdigest()


def credential_injection_target(injection: dict[str, Any]) -> tuple[str, str] | None:
    if not isinstance(injection, dict):
        return None
    injection_type = injection.get("type", "bearer")
    if not isinstance(injection_type, str):
        return None

    def target_value(name: str, default: str) -> str | None:
        value = injection.get(name, default)
        return value if isinstance(value, str) else None

    if injection_type == "bearer":
        value = target_value("header", "Authorization")
        return ("header", value.lower()) if value is not None else None
    if injection_type == "header":
        value = target_value("name", "X-Api-Key")
        return ("header", value.lower()) if value is not None else None
    if injection_type == "basic":
        value = target_value("header", "Authorization")
        return ("header", value.lower()) if value is not None else None
    if injection_type == "cookie":
        return "header", "cookie"
    if injection_type == "query":
        value = target_value("name", "access_token")
        return ("query", value) if value is not None else None
    return None


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def policy_hash(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(signature_payload(value)).encode("utf-8")).hexdigest()


def signature_payload(value: dict[str, Any]) -> dict[str, Any]:
    unsigned = copy.deepcopy(value)
    metadata = unsigned.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("signature", None)
    return unsigned


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _load_policy_private_key() -> Ed25519PrivateKey:
    ensure_data_dirs()
    if POLICY_SIGNING_KEY_PATH.exists():
        key = serialization.load_pem_private_key(POLICY_SIGNING_KEY_PATH.read_bytes(), password=None)
        _write_policy_public_key(key.public_key())
        return key
    key = Ed25519PrivateKey.generate()
    POLICY_SIGNING_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(POLICY_SIGNING_KEY_PATH, 0o600)
    _write_policy_public_key(key.public_key())
    return key


def _write_policy_public_key(public_key: Ed25519PublicKey) -> None:
    POLICY_SIGNING_PUBLIC_KEY_PATH.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    os.chmod(POLICY_SIGNING_PUBLIC_KEY_PATH, 0o644)


def policy_public_key() -> Ed25519PublicKey:
    return _load_policy_private_key().public_key()


def policy_public_key_pem() -> str:
    return policy_public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def policy_public_key_hash() -> str:
    der = policy_public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


def sign_policy_bundle(raw: dict[str, Any]) -> dict[str, Any]:
    signed = copy.deepcopy(raw)
    signed.setdefault("metadata", {})
    signed["metadata"]["signingKeyId"] = policy_public_key_hash()
    signed["metadata"].pop("signature", None)
    signature = _load_policy_private_key().sign(canonical_json(signature_payload(signed)).encode("utf-8"))
    signed["metadata"]["signature"] = "ed25519:" + _b64e(signature)
    return signed


def verify_policy_signature(raw: dict[str, Any]) -> None:
    signature_value = (raw.get("metadata") or {}).get("signature")
    if not isinstance(signature_value, str) or not signature_value.startswith("ed25519:"):
        raise PolicyBundleError("policy bundle must include metadata.signature using ed25519")
    signature = _b64d(signature_value.split(":", 1)[1])
    try:
        policy_public_key().verify(signature, canonical_json(signature_payload(raw)).encode("utf-8"))
    except InvalidSignature as exc:
        raise PolicyBundleError("policy bundle signature verification failed") from exc


def _load_schema(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def validate_policy_schema(raw: dict[str, Any]) -> None:
    try:
        from jsonschema import Draft202012Validator, ValidationError
    except Exception as exc:
        raise PolicyBundleError("jsonschema package is required for policy validation") from exc

    bundle_schema = _load_schema(SCHEMA_DIR / "policy-bundle.v1.schema.json")
    try:
        Draft202012Validator(bundle_schema).validate(raw)
        for route in raw.get("routes") or []:
            adapter = route.get("adapter") or {}
            adapter_type = adapter.get("type")
            if not adapter_type:
                continue
            schema_path = SCHEMA_DIR / "adapters" / f"{adapter_type}.schema.json"
            if schema_path.exists():
                Draft202012Validator(_load_schema(schema_path)).validate(adapter.get("config") or {})
    except ValidationError as exc:
        path = ".".join(str(item) for item in exc.absolute_path)
        location = f" at {path}" if path else ""
        raise PolicyBundleError(f"policy schema validation failed{location}: {exc.message}") from exc


def _path_template_to_regex(template: str) -> re.Pattern[str]:
    if not template.startswith("/"):
        raise PolicyBundleError(f"path template must start with /: {template}")
    segments = template.strip("/").split("/") if template != "/" else []
    if "**" in segments[:-1]:
        raise PolicyBundleError(f"recursive wildcard must be the final path segment: {template}")
    if template.endswith("/**"):
        prefix = re.escape(template[:-3].rstrip("/"))
        return re.compile(rf"^{prefix}(?:/.*)?$")

    parts: list[str] = []
    for segment in template.strip("/").split("/"):
        if segment == "*":
            parts.append(r"[^/]+")
        elif segment == "**":
            parts.append(r".*")
        elif segment.startswith("{") and segment.endswith("}"):
            name = segment[1:-1]
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                raise PolicyBundleError(f"invalid path variable {segment} in {template}")
            parts.append(rf"(?P<{name}>[^/]+)")
        else:
            parts.append(re.escape(segment))
    body = "/".join(parts)
    return re.compile(rf"^/{body}/?$")


def _path_specificity(template: str) -> tuple[int, ...]:
    scores: list[int] = []
    for segment in template.strip("/").split("/"):
        if segment == "**":
            scores.append(0)
        elif segment == "*":
            scores.append(1)
        elif segment.startswith("{") and segment.endswith("}"):
            scores.append(2)
        else:
            scores.append(3)
    return tuple(scores)


def _path_shape(template: str) -> tuple[str, ...]:
    shape: list[str] = []
    for segment in template.strip("/").split("/"):
        if segment.startswith("{") and segment.endswith("}"):
            shape.append("{}")
        else:
            shape.append(segment)
    return tuple(shape)


def parse_bounded_pattern(pattern: str) -> tuple[str, tuple[tuple[int, int], ...], int, int] | None:
    if len(pattern) > 256 or not pattern.isascii() or not pattern.startswith("^") or not pattern.endswith("$"):
        return None
    body = pattern[1:-1]
    class_start = body.find("[")
    if class_start < 0:
        return None
    class_end = body.find("]", class_start + 1)
    if class_end < 0:
        return None
    prefix = body[:class_start]
    if any(character in prefix for character in "\\[]{}"):
        return None
    character_class = body[class_start + 1 : class_end].encode("ascii")
    if not character_class:
        return None
    quantifier = body[class_end + 1 :]
    match = re.fullmatch(r"\{([0-9]+),([0-9]+)\}", quantifier)
    if match is None:
        return None
    minimum, maximum = (int(value) for value in match.groups())
    if minimum > maximum or maximum > 4096:
        return None
    ranges: list[tuple[int, int]] = []
    index = 0
    while index < len(character_class):
        if index + 2 < len(character_class) and character_class[index + 1] == ord("-"):
            start, end = character_class[index], character_class[index + 2]
            if start > end:
                return None
            ranges.append((start, end))
            index += 3
        else:
            ranges.append((character_class[index], character_class[index]))
            index += 1
    return prefix, tuple(ranges), minimum, maximum


def bounded_pattern_matches(pattern: str, value: str) -> bool | None:
    parsed = parse_bounded_pattern(pattern)
    if parsed is None:
        return None
    prefix, ranges, minimum, maximum = parsed
    if not value.startswith(prefix):
        return False
    remainder = value[len(prefix) :].encode("utf-8")
    return minimum <= len(remainder) <= maximum and all(
        any(start <= byte <= end for start, end in ranges) for byte in remainder
    )


def _validate_safe_pattern(route_id: str, constraint_id: str, field: str, rule: dict[str, Any]) -> None:
    pattern = rule.get("pattern")
    if pattern is None:
        return
    if not isinstance(pattern, str) or parse_bounded_pattern(pattern) is None:
        raise PolicyBundleError(
            f"route {route_id} constraint {constraint_id} field {field} pattern must use the bounded runtime grammar"
        )
    maximum_length = rule.get("maxLength")
    if type(maximum_length) is not int or not 0 <= maximum_length <= 4096:
        raise PolicyBundleError(
            f"route {route_id} constraint {constraint_id} field {field} pattern requires maxLength <= 4096"
        )


def _validate_field_rule(
    route_id: str,
    constraint_id: str,
    field: str,
    rule: dict[str, Any],
    *,
    form: bool = False,
) -> None:
    unknown = sorted(set(rule) - FIELD_RULE_FIELDS)
    if unknown:
        raise PolicyBundleError(
            f"route {route_id} constraint {constraint_id} field {field} has unsupported rules: {', '.join(unknown)}"
        )
    if "required" in rule and not isinstance(rule["required"], bool):
        raise PolicyBundleError(f"route {route_id} constraint {constraint_id} field {field} required must be boolean")
    expected_type = rule.get("type")
    allowed_types = FIELD_RULE_TYPES - ({"object", "null"} if form else set())
    if expected_type is not None and (
        not isinstance(expected_type, str) or expected_type not in allowed_types
    ):
        raise PolicyBundleError(f"route {route_id} constraint {constraint_id} field {field} has unsupported type")
    typed_rule_families = (
        (("minLength", "maxLength", "pattern"), {"string"}, "string"),
        (("min", "max"), {"number", "integer"}, "number or integer"),
        (("minItems", "maxItems"), {"array"}, "array"),
    )
    for names, compatible_types, label in typed_rule_families:
        configured = [name for name in names if name in rule]
        if configured and expected_type not in compatible_types:
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} field {field} rules "
                f"{', '.join(configured)} require explicit type {label}"
            )
    enum = rule.get("enum")
    if enum is not None and (
        not isinstance(enum, list)
        or not enum
        or any(value in enum[:index] for index, value in enumerate(enum))
    ):
        raise PolicyBundleError(
            f"route {route_id} constraint {constraint_id} field {field} enum must be non-empty and unique"
        )
    for minimum_name, maximum_name in (("minLength", "maxLength"), ("minItems", "maxItems")):
        for name in (minimum_name, maximum_name):
            if name in rule and (type(rule[name]) is not int or rule[name] < 0):
                raise PolicyBundleError(
                    f"route {route_id} constraint {constraint_id} field {field} {name} must be a non-negative integer"
                )
        if minimum_name in rule and maximum_name in rule and rule[minimum_name] > rule[maximum_name]:
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} field {field} {minimum_name} must not exceed {maximum_name}"
            )
    for name in ("min", "max"):
        value = rule.get(name)
        if value is not None and (
            not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value)
        ):
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} field {field} {name} must be a finite number"
            )
    if rule.get("min") is not None and rule.get("max") is not None and rule["min"] > rule["max"]:
        raise PolicyBundleError(
            f"route {route_id} constraint {constraint_id} field {field} min must not exceed max"
        )
    _validate_safe_pattern(route_id, constraint_id, field, rule)


def _validate_credential_injection(credential_id: str, raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PolicyBundleError(f"credential {credential_id} injection must be an object")
    injection = dict(raw)
    injection_type = injection.get("type")
    if not isinstance(injection_type, str) or injection_type not in CREDENTIAL_INJECTION_FIELDS:
        raise PolicyBundleError(f"credential {credential_id} has unsupported injection type {injection_type!r}")
    unsupported_fields = set(injection) - CREDENTIAL_INJECTION_FIELDS[injection_type]
    if unsupported_fields:
        rendered = ", ".join(repr(name) for name in sorted(unsupported_fields, key=repr))
        raise PolicyBundleError(
            f"credential {credential_id} {injection_type} injection has unsupported fields: {rendered}"
        )

    field = injection.get("field")
    if field is not None and (
        not isinstance(field, str)
        or len(field) > 256
        or CREDENTIAL_FIELD_PATH_RE.fullmatch(field) is None
    ):
        raise PolicyBundleError(f"credential {credential_id} has an invalid injection field")

    prefix = injection.get("prefix")
    if prefix is not None and (
        not isinstance(prefix, str)
        or len(prefix) > 128
        or "\r" in prefix
        or "\n" in prefix
    ):
        raise PolicyBundleError(f"credential {credential_id} has an invalid injection prefix")

    if injection_type == "basic":
        username = injection.get("username")
        if (
            not isinstance(username, str)
            or not username
            or len(username) > 256
            or any(
                character == ":"
                or character.isspace()
                or ord(character) < 32
                or ord(character) == 127
                for character in username
            )
        ):
            raise PolicyBundleError(f"credential {credential_id} has an invalid Basic username")

    if injection_type in {"header", "query", "cookie"}:
        name = injection.get("name")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 128
            or HTTP_HEADER_NAME_RE.fullmatch(name) is None
        ):
            raise PolicyBundleError(f"credential {credential_id} has an invalid {injection_type} injection name")

    target = credential_injection_target(injection)
    if target is None:
        raise PolicyBundleError(f"credential {credential_id} has no enforceable injection target")
    location, name = target
    if location == "header":
        if not name or len(name) > 128 or HTTP_HEADER_NAME_RE.fullmatch(name) is None:
            raise PolicyBundleError(f"credential {credential_id} has an invalid injection header")
        reserved_target_is_canonical = (
            injection_type in {"bearer", "basic"} and name == "authorization"
        ) or (injection_type == "cookie" and name == "cookie")
        if (
            (name in NON_FORWARDABLE_AGENT_HEADERS and not reserved_target_is_canonical)
            or name.startswith("x-serverware-")
        ):
            raise PolicyBundleError(f"credential {credential_id} uses a forbidden injection header {name}")
    elif not name or len(name) > 128 or any(ord(character) < 33 or ord(character) == 127 for character in name):
        raise PolicyBundleError(f"credential {credential_id} has an invalid injection query key")
    return injection


def _validate_managed_oauth_injection(credential_id: str, provider: str, injection: dict[str, Any]) -> None:
    if provider.strip().lower() not in MANAGED_OAUTH_PROVIDERS:
        return
    if (
        injection.get("type") != "bearer"
        or str(injection.get("header") or "Authorization").lower() != "authorization"
        or injection.get("field") != "access_token"
        or injection.get("prefix", "Bearer ") != "Bearer "
    ):
        raise PolicyBundleError(
            f"OAuth credential {credential_id} must inject only access_token as canonical Authorization Bearer"
        )


def _validate_generic_required_headers(
    route_id: str,
    request_config: dict[str, Any],
    allowed_headers: set[str],
) -> set[str]:
    raw = request_config.get("requiredHeaders") or {}
    if not isinstance(raw, dict) or len(raw) > 16:
        raise PolicyBundleError(
            f"route {route_id} generic.rest requiredHeaders must be an object with at most 16 entries"
        )
    required_headers: set[str] = set()
    for name, rule in raw.items():
        if (
            not isinstance(name, str)
            or name != name.lower()
            or len(name) > 128
            or HTTP_HEADER_NAME_RE.fullmatch(name) is None
        ):
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header names must be lower-case HTTP field names"
            )
        if name not in allowed_headers or name in NON_FORWARDABLE_AGENT_HEADERS:
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header {name} is not an allowed forwarded header"
            )
        if not isinstance(rule, dict):
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header {name} rule must be an object"
            )
        unknown = sorted(set(rule) - REQUIRED_REQUEST_HEADER_RULE_FIELDS)
        if unknown:
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header {name} has unsupported rules: {', '.join(unknown)}"
            )
        if rule.get("type") != "string":
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header {name} type must be string"
            )
        minimum = rule.get("minLength")
        maximum = rule.get("maxLength")
        if (
            type(minimum) is not int
            or type(maximum) is not int
            or minimum < 1
            or maximum < minimum
            or maximum > 8192
        ):
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header {name} must define lengths between 1 and 8192"
            )
        pattern = rule.get("pattern")
        if pattern is not None and (
            not isinstance(pattern, str)
            or parse_bounded_pattern(pattern) is None
            or maximum > 4096
        ):
            raise PolicyBundleError(
                f"route {route_id} generic.rest required header {name} pattern must use the bounded runtime grammar"
            )
        required_headers.add(name)
    return required_headers


@dataclass(frozen=True)
class ProxyAuthorizationPolicy:
    scheme: str = "Bearer"
    token_sha256: str | None = None
    source_cidrs: tuple[str, ...] = ()
    expires_at_epoch_ms: int | None = None
    legacy_exact: str | None = None

    @property
    def networks(self) -> tuple[ipaddress._BaseNetwork, ...]:
        return tuple(ipaddress.ip_network(cidr, strict=False) for cidr in self.source_cidrs)

    def matches(self, client_ip: str | None, raw_header: str | None) -> bool:
        if not raw_header:
            return False
        if self.legacy_exact is not None:
            return hmac.compare_digest(raw_header, self.legacy_exact)
        if self.expires_at_epoch_ms is not None and int(time.time() * 1000) >= self.expires_at_epoch_ms:
            return False
        if self.source_cidrs:
            if not client_ip:
                return False
            try:
                ip = ipaddress.ip_address(client_ip)
            except ValueError:
                return False
            if not any(ip in network for network in self.networks):
                return False
        scheme, _, token = raw_header.strip().partition(" ")
        if not token or scheme.lower() != self.scheme.lower():
            return False
        digest = "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()
        return bool(self.token_sha256) and hmac.compare_digest(digest, self.token_sha256)

    @classmethod
    def from_raw(cls, raw: Any) -> "ProxyAuthorizationPolicy | None":
        if raw is None:
            return None
        if isinstance(raw, str):
            return cls(legacy_exact=raw)
        if not isinstance(raw, dict):
            raise PolicyBundleError("principal proxyAuthorization must be a string or object")
        return cls(
            scheme=str(raw.get("scheme") or "Bearer"),
            token_sha256=str(raw.get("tokenSha256") or ""),
            source_cidrs=tuple(raw.get("sourceCidrs") or ()),
            expires_at_epoch_ms=int(raw["expiresAtEpochMs"]) if raw.get("expiresAtEpochMs") is not None else None,
        )


def _header_value(headers: Any, name: str) -> str | None:
    value = headers.get(name)
    if value is not None:
        return value
    lower = name.lower()
    value = headers.get(lower)
    if value is not None:
        return value
    for key, candidate in getattr(headers, "items", lambda: [])():
        if str(key).lower() == lower:
            return candidate
    return None


@dataclass(frozen=True)
class PrincipalPolicy:
    id: str
    source_cidrs: tuple[str, ...] = ()
    required_headers: dict[str, str] = field(default_factory=dict)
    proxy_authorization: ProxyAuthorizationPolicy | None = None

    @property
    def networks(self) -> tuple[ipaddress._BaseNetwork, ...]:
        return tuple(ipaddress.ip_network(cidr, strict=False) for cidr in self.source_cidrs)

    def matches(self, client_ip: str | None, headers: Any) -> bool:
        if self.source_cidrs:
            if not client_ip:
                return False
            try:
                ip = ipaddress.ip_address(client_ip)
            except ValueError:
                return False
            if not any(ip in network for network in self.networks):
                return False

        for name, expected in self.required_headers.items():
            if _header_value(headers, name) != expected:
                return False

        if self.proxy_authorization and not self.proxy_authorization.matches(client_ip, _header_value(headers, "Proxy-Authorization")):
            return False

        return True


@dataclass(frozen=True)
class CredentialPolicy:
    id: str
    provider: str = "generic"
    provider_subject: str | None = None
    scopes: tuple[str, ...] = ()
    injection: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RoutePolicy:
    id: str
    principals: tuple[str, ...]
    host: str
    port: int
    scheme: str
    methods: frozenset[str]
    path_templates: tuple[str, ...]
    path_regexes: tuple[re.Pattern[str], ...]
    credential_ref: str | None
    adapter_type: str
    adapter_config: dict[str, Any]
    constraints: tuple[dict[str, Any], ...] = ()
    jit: dict[str, Any] = field(default_factory=dict)

    def match_path(self, path: str) -> dict[str, str] | None:
        candidate = self.match_path_with_specificity(path)
        return candidate[0] if candidate else None

    def match_path_with_specificity(self, path: str) -> tuple[dict[str, str], tuple[int, ...]] | None:
        matches: list[tuple[dict[str, str], tuple[int, ...]]] = []
        for template, regex in zip(self.path_templates, self.path_regexes, strict=True):
            match = regex.match(path)
            if match:
                matches.append((match.groupdict(), _path_specificity(template)))
        return max(matches, key=lambda item: item[1]) if matches else None


@dataclass(frozen=True)
class RouteMatch:
    route: RoutePolicy
    params: dict[str, str]


@dataclass(frozen=True)
class PolicySnapshot:
    raw: dict[str, Any]
    hash: str
    principals: dict[str, PrincipalPolicy]
    credentials: dict[str, CredentialPolicy]
    routes: tuple[RoutePolicy, ...]

    def identify_principal(self, client_ip: str | None, headers: Any) -> PrincipalPolicy | None:
        for principal in self.principals.values():
            if principal.matches(client_ip, headers):
                return principal
        return None

    def match_route(self, scheme: str, host: str, port: int, method: str, path: str, principal_id: str) -> RouteMatch | None:
        normalized_host = host.lower().rstrip(".")
        normalized_method = method.upper()
        matches: list[tuple[tuple[int, ...], RoutePolicy, dict[str, str]]] = []
        for route in self.routes:
            if route.scheme != scheme.lower():
                continue
            if route.host != normalized_host:
                continue
            if route.port != port:
                continue
            if principal_id not in route.principals and "*" not in route.principals:
                continue
            path_match = route.match_path_with_specificity(path)
            if path_match is None:
                continue
            if normalized_method not in route.methods:
                continue
            params, specificity = path_match
            matches.append((specificity, route, params))
        if not matches:
            return None
        best_specificity = max(item[0] for item in matches)
        best = [item for item in matches if item[0] == best_specificity]
        if len(best) != 1:
            return None
        _, route, params = best[0]
        return RouteMatch(route=route, params=params)


_SNAPSHOT_CACHE: tuple[float | None, PolicySnapshot | None] = (None, None)


def _load_raw_policy(path: Path) -> dict[str, Any]:
    text = path.read_text()
    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            from ruamel.yaml import YAML
        except Exception as exc:
            raise PolicyBundleError("YAML policy bundles require ruamel.yaml") from exc
        loaded = YAML(typ="safe").load(text)
    else:
        loaded = json.loads(text)
    if not isinstance(loaded, dict):
        raise PolicyBundleError("policy bundle must be an object")
    return loaded


def _parse_policy_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
        value,
    ) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def _parse_clock_minutes(value: Any) -> int | None:
    if not isinstance(value, str) or re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value) is None:
        return None
    hour, minute = value.split(":", 1)
    return int(hour) * 60 + int(minute)


def _validate_constraints(route_id: str, constraints: Any) -> tuple[dict[str, Any], ...]:
    if constraints is None:
        return ()
    if not isinstance(constraints, list):
        raise PolicyBundleError(f"route {route_id} constraints must be an array")
    compiled: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, constraint in enumerate(constraints):
        if not isinstance(constraint, dict):
            raise PolicyBundleError(f"route {route_id} constraint {index} must be an object")
        constraint_id = str(constraint.get("id") or "")
        if not constraint_id:
            raise PolicyBundleError(f"route {route_id} constraint {index} must define id")
        if constraint_id in seen_ids:
            raise PolicyBundleError(f"route {route_id} has duplicate constraint id {constraint_id}")
        seen_ids.add(constraint_id)
        constraint_type = str(constraint.get("type") or "")
        if constraint_type not in SUPPORTED_CONSTRAINTS:
            raise PolicyBundleError(f"route {route_id} constraint {constraint_id} has unsupported type {constraint_type}")
        irrelevant_fields = sorted(set(constraint) - CONSTRAINT_COMMON_FIELDS - CONSTRAINT_TYPE_FIELDS[constraint_type])
        if irrelevant_fields:
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} type {constraint_type} has unsupported fields: "
                f"{', '.join(irrelevant_fields)}"
            )
        phase = constraint.get("phase", "request")
        expected_phase = "request" if constraint_type in REQUEST_CONSTRAINTS else "response"
        if phase != expected_phase:
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} type {constraint_type} "
                f"must use phase {expected_phase}"
            )
        store = constraint.get("store", "local")
        if store not in {"local", "shared"}:
            raise PolicyBundleError(f"route {route_id} constraint {constraint_id} has invalid store {store}")
        if constraint.get("operations") is not None and constraint_type not in {
            "responseDateWindow",
            "responseJson",
        }:
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} operations are supported only for response constraints"
            )
        if constraint_type == "rateLimit":
            max_count = constraint.get("max")
            window_seconds = constraint.get("windowSeconds")
            if not isinstance(max_count, int) or isinstance(max_count, bool) or not 1 <= max_count <= 1_000_000_000:
                raise PolicyBundleError(
                    f"route {route_id} rateLimit {constraint_id} must define integer max between 1 and 1000000000"
                )
            if not isinstance(window_seconds, int) or isinstance(window_seconds, bool) or not 1 <= window_seconds <= 31_536_000:
                raise PolicyBundleError(
                    f"route {route_id} rateLimit {constraint_id} must define windowSeconds between 1 and 31536000"
                )
            raw_key_policy = constraint.get("key")
            if raw_key_policy is not None and not isinstance(raw_key_policy, dict):
                raise PolicyBundleError(f"route {route_id} rateLimit {constraint_id} key must be an object")
            key_policy = raw_key_policy or {}
            scope = key_policy.get("scope") or ["principal", "credential", "route", "operation"]
            allowed_scope = {"principal", "credential", "credentialVersion", "route", "operation"}
            if not isinstance(scope, list) or not scope or any(
                not isinstance(item, str) or item not in allowed_scope for item in scope
            ):
                raise PolicyBundleError(f"route {route_id} rateLimit {constraint_id} has unsupported key scope")
            operation_fields = key_policy.get("operationFields") or []
            if not isinstance(operation_fields, list) or any(
                not isinstance(field, str)
                or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", field) is None
                for field in operation_fields
            ):
                raise PolicyBundleError(f"route {route_id} rateLimit {constraint_id} has invalid operationFields")
        elif constraint_type == "operationPolicy":
            if not (constraint.get("allowedOperations") or constraint.get("deniedOperations")):
                raise PolicyBundleError(
                    f"route {route_id} operationPolicy {constraint_id} must define allowedOperations or deniedOperations"
                )
        elif constraint_type in {"queryDateWindow", "queryNumericBounds"}:
            if not constraint.get("parameters"):
                raise PolicyBundleError(f"route {route_id} {constraint_type} {constraint_id} must define parameters")
            if constraint_type == "queryDateWindow" and int(constraint.get("maxAgeDays") or 0) < 1:
                raise PolicyBundleError(f"route {route_id} queryDateWindow {constraint_id} must define maxAgeDays >= 1")
            if constraint_type == "queryDateWindow" and not constraint.get("formats"):
                raise PolicyBundleError(f"route {route_id} queryDateWindow {constraint_id} must define formats")
            if constraint_type == "queryDateWindow":
                formats = constraint.get("formats")
                allowed_formats = {"rfc3339", "date", "epochSeconds", "epochMillis"}
                if (
                    not isinstance(formats, list)
                    or any(not isinstance(item, str) or item not in allowed_formats for item in formats)
                    or len(formats) != len(set(formats))
                ):
                    raise PolicyBundleError(f"route {route_id} queryDateWindow {constraint_id} has invalid formats")
            if constraint_type == "queryNumericBounds":
                minimum = constraint.get("min")
                maximum = constraint.get("max")
                if minimum is None and maximum is None:
                    raise PolicyBundleError(
                        f"route {route_id} queryNumericBounds {constraint_id} must define min or max"
                    )
                if minimum is not None and maximum is not None and minimum > maximum:
                    raise PolicyBundleError(
                        f"route {route_id} queryNumericBounds {constraint_id} min must not exceed max"
                    )
        elif constraint_type == "requestTimeWindow":
            if constraint.get("timezone") != "UTC":
                raise PolicyBundleError(
                    f"route {route_id} requestTimeWindow {constraint_id} must use timezone UTC"
                )
            if not any(constraint.get(field) for field in ("notBefore", "notAfter", "weekdays", "dailyWindows")):
                raise PolicyBundleError(
                    f"route {route_id} requestTimeWindow {constraint_id} must define at least one bound"
                )
            not_before = (
                _parse_policy_timestamp(constraint.get("notBefore")) if constraint.get("notBefore") is not None else None
            )
            not_after = (
                _parse_policy_timestamp(constraint.get("notAfter")) if constraint.get("notAfter") is not None else None
            )
            if constraint.get("notBefore") is not None and not_before is None:
                raise PolicyBundleError(
                    f"route {route_id} requestTimeWindow {constraint_id} notBefore must be RFC3339"
                )
            if constraint.get("notAfter") is not None and not_after is None:
                raise PolicyBundleError(
                    f"route {route_id} requestTimeWindow {constraint_id} notAfter must be RFC3339"
                )
            if not_before is not None and not_after is not None and not_before >= not_after:
                raise PolicyBundleError(
                    f"route {route_id} requestTimeWindow {constraint_id} notBefore must precede notAfter"
                )
            weekdays = constraint.get("weekdays")
            allowed_weekdays = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
            if weekdays is not None and (
                not isinstance(weekdays, list)
                or not weekdays
                or any(not isinstance(day, str) or day not in allowed_weekdays for day in weekdays)
                or len(weekdays) != len(set(weekdays))
            ):
                raise PolicyBundleError(
                    f"route {route_id} requestTimeWindow {constraint_id} has invalid weekdays"
                )
            daily_windows = constraint.get("dailyWindows")
            if daily_windows is not None:
                if not isinstance(daily_windows, list) or not daily_windows:
                    raise PolicyBundleError(
                        f"route {route_id} requestTimeWindow {constraint_id} has invalid dailyWindows"
                    )
                intervals: list[tuple[int, int]] = []
                for window in daily_windows:
                    if not isinstance(window, dict) or set(window) != {"start", "end"}:
                        raise PolicyBundleError(
                            f"route {route_id} requestTimeWindow {constraint_id} has invalid daily window"
                        )
                    start = _parse_clock_minutes(window.get("start"))
                    end = _parse_clock_minutes(window.get("end"))
                    if start is None or end is None or start >= end:
                        raise PolicyBundleError(
                            f"route {route_id} requestTimeWindow {constraint_id} daily windows must be increasing UTC times"
                        )
                    intervals.append((start, end))
                intervals.sort()
                if any(start < previous_end for (_, previous_end), (start, _) in zip(intervals, intervals[1:])):
                    raise PolicyBundleError(
                        f"route {route_id} requestTimeWindow {constraint_id} daily windows must not overlap"
                    )
        elif constraint_type in {"jsonBody", "formBody"}:
            if not constraint.get("allowedFields"):
                raise PolicyBundleError(
                    f"route {route_id} {constraint_type} {constraint_id} must define non-empty allowedFields "
                    "so unknown fields fail closed"
                )
            for field, rule in (constraint.get("fields") or {}).items():
                if not isinstance(rule, dict):
                    raise PolicyBundleError(
                        f"route {route_id} {constraint_type} {constraint_id} field {field} rule must be an object"
                    )
                _validate_field_rule(
                    route_id,
                    constraint_id,
                    str(field),
                    rule,
                    form=constraint_type == "formBody",
                )
        elif constraint_type == "responseJson":
            if "required" in constraint and not isinstance(constraint["required"], bool):
                raise PolicyBundleError(
                    f"route {route_id} responseJson {constraint_id} required must be boolean"
                )
            fields = constraint.get("fields")
            if not isinstance(fields, dict) or not fields:
                raise PolicyBundleError(
                    f"route {route_id} responseJson {constraint_id} must define non-empty fields"
                )
            items = constraint.get("items")
            if items is not None and (
                not isinstance(items, list)
                or not items
                or any(
                    not isinstance(item, str)
                    or len(item) > 256
                    or RESPONSE_FIELD_PATH_RE.fullmatch(item) is None
                    for item in items
                )
                or len(items) != len(set(items))
            ):
                raise PolicyBundleError(
                    f"route {route_id} responseJson {constraint_id} has invalid items"
                )
            for field, rule in fields.items():
                if (
                    not isinstance(field, str)
                    or len(field) > 256
                    or RESPONSE_FIELD_PATH_RE.fullmatch(field) is None
                    or not isinstance(rule, dict)
                    or not rule
                ):
                    raise PolicyBundleError(
                        f"route {route_id} responseJson {constraint_id} field {field} has an invalid rule"
                    )
                _validate_field_rule(route_id, constraint_id, field, rule)
        elif constraint_type == "responseDateWindow":
            if int(constraint.get("maxAgeDays") or 0) < 1:
                raise PolicyBundleError(f"route {route_id} responseDateWindow {constraint_id} must define maxAgeDays >= 1")
            if not constraint.get("dateFields"):
                raise PolicyBundleError(f"route {route_id} responseDateWindow {constraint_id} must define dateFields")
            if not constraint.get("formats"):
                raise PolicyBundleError(f"route {route_id} responseDateWindow {constraint_id} must define formats")
            formats = constraint.get("formats")
            allowed_formats = {"rfc3339", "date", "epochSeconds", "epochMillis"}
            if (
                not isinstance(formats, list)
                or any(not isinstance(item, str) or item not in allowed_formats for item in formats)
                or len(formats) != len(set(formats))
            ):
                raise PolicyBundleError(f"route {route_id} responseDateWindow {constraint_id} has invalid formats")
        if constraint_type in {"responseDateWindow", "responseJson"}:
            operations = constraint.get("operations")
            if operations is not None and (
                not isinstance(operations, list)
                or not operations
                or any(
                    not isinstance(operation, str)
                    or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", operation) is None
                    for operation in operations
                )
                or len(set(operations)) != len(operations)
            ):
                raise PolicyBundleError(
                    f"route {route_id} {constraint_type} {constraint_id} has invalid operations"
                )
        if constraint.get("extensions"):
            raise PolicyBundleError(
                f"route {route_id} constraint {constraint_id} declares unattested extensions"
            )
        compiled.append(dict(constraint))
    return tuple(compiled)


def _validate_provider_account_rate_limits(
    route_id: str,
    constraints: tuple[dict[str, Any], ...],
    credential: CredentialPolicy | None,
) -> None:
    identity_scopes = {"principal", "credential", "credentialVersion"}
    for constraint in constraints:
        if constraint.get("type") != "rateLimit":
            continue
        key = constraint.get("key") or {}
        operation_fields = set(key.get("operationFields") or [])
        if PROVIDER_ACCOUNT_OPERATION_FIELD not in operation_fields:
            continue
        scope = set(key.get("scope") or ["principal", "credential", "route", "operation"])
        conflicting = sorted(scope.intersection(identity_scopes))
        if conflicting:
            raise PolicyBundleError(
                f"route {route_id} provider-account rate limit {constraint.get('id')} "
                f"must not be partitioned by {', '.join(conflicting)}"
            )
        if credential is None or provider_account_scope_value(
            credential.provider, credential.provider_subject
        ) is None:
            raise PolicyBundleError(
                f"route {route_id} provider-account rate limit {constraint.get('id')} "
                "requires a signed credential providerSubject"
            )


def _validate_response_body_limit(
    route_id: str,
    profile: dict[str, Any],
    profile_name: str,
    maximum: int,
) -> None:
    value = profile.get("maxBodyBytes")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > maximum:
        raise PolicyBundleError(
            f"route {route_id} {profile_name} maxBodyBytes must be an integer between 1 and {maximum}"
        )


def _validate_response_field_paths(
    route_id: str,
    profile: dict[str, Any],
    profile_name: str,
) -> tuple[str, ...]:
    fields = profile.get("allowedFields")
    if (
        not isinstance(fields, list)
        or not fields
        or len(fields) > 64
        or any(
            not isinstance(field, str)
            or len(field) > 256
            or RESPONSE_FIELD_PATH_RE.fullmatch(field) is None
            for field in fields
        )
        or len(fields) != len(set(fields))
    ):
        raise PolicyBundleError(
            f"route {route_id} {profile_name} must define 1-64 unique allowedFields using bounded dotted paths"
        )
    return tuple(fields)


def _validate_response_headers(
    route_id: str,
    profile: dict[str, Any],
    profile_name: str,
) -> None:
    headers = profile.get("allowedHeaders")
    if not isinstance(headers, list) or len(headers) > len(SAFE_RESPONSE_HEADERS):
        raise PolicyBundleError(f"route {route_id} {profile_name} must define bounded allowedHeaders")
    if any(not isinstance(header, str) or header not in SAFE_RESPONSE_HEADERS for header in headers):
        raise PolicyBundleError(
            f"route {route_id} {profile_name} allowedHeaders must be lower-case safe response headers"
        )
    if len(headers) != len(set(headers)):
        raise PolicyBundleError(f"route {route_id} {profile_name} allowedHeaders must be unique")


def _validate_bounded_response_profiles(
    route_id: str,
    response: Any,
    adapter_name: str,
) -> tuple[str, ...]:
    if not isinstance(response, dict):
        raise PolicyBundleError(f"route {route_id} {adapter_name} policy must define response enforcement")
    profile_name = f"{adapter_name} success response"
    _validate_response_body_limit(route_id, response, profile_name, MAX_PROVIDER_RESPONSE_BODY_BYTES)
    fields = _validate_response_field_paths(route_id, response, profile_name)
    _validate_response_headers(route_id, response, profile_name)

    error = response.get("error")
    if not isinstance(error, dict):
        raise PolicyBundleError(f"route {route_id} {adapter_name} policy must define an error response profile")
    if error.get("mode") != "json":
        raise PolicyBundleError(f"route {route_id} {adapter_name} error response mode must be json")
    if error.get("onInvalid") != "block":
        raise PolicyBundleError(f"route {route_id} {adapter_name} invalid error responses must block")
    error_profile_name = f"{adapter_name} error response"
    _validate_response_body_limit(route_id, error, error_profile_name, MAX_PROVIDER_ERROR_BODY_BYTES)
    _validate_response_field_paths(route_id, error, error_profile_name)
    _validate_response_headers(route_id, error, error_profile_name)
    return fields


def _validate_optional_response_release_contract(
    route_id: str,
    response: dict[str, Any],
    adapter_name: str,
) -> None:
    if response.get("mode") == "json":
        _validate_response_field_paths(route_id, response, f"{adapter_name} success response")
    if "allowedHeaders" in response:
        _validate_response_headers(route_id, response, f"{adapter_name} success response")
    error = response.get("error")
    if error is None:
        return
    if not isinstance(error, dict) or error.get("mode") != "json" or error.get("onInvalid") != "block":
        raise PolicyBundleError(
            f"route {route_id} {adapter_name} error response must use bounded json and block on invalid"
        )
    _validate_response_body_limit(
        route_id, error, f"{adapter_name} error response", MAX_PROVIDER_ERROR_BODY_BYTES
    )
    _validate_response_field_paths(route_id, error, f"{adapter_name} error response")
    _validate_response_headers(route_id, error, f"{adapter_name} error response")


def _validate_adapter_security_invariants(
    route_id: str,
    adapter_type: str,
    adapter_config: dict[str, Any],
    credential_ref: str | None,
    jit: dict[str, Any],
    methods: frozenset[str],
    paths: tuple[str, ...],
    constraints: tuple[dict[str, Any], ...],
) -> None:
    if adapter_type == "gmail.v1":
        if not credential_ref:
            raise PolicyBundleError(f"route {route_id} Gmail policy must bind a credential")
        if adapter_config.get("forceQuery") is not True:
            raise PolicyBundleError(f"route {route_id} Gmail policy must force the bounded age query")
        if adapter_config.get("allowMessageGetOnlyFromPriorSearch") is not True:
            raise PolicyBundleError(f"route {route_id} Gmail policy must require prior age proof for message reads")
        for field_name in ("maxAgeDays", "maxResults", "cacheTtlSeconds"):
            value = adapter_config.get(field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise PolicyBundleError(f"route {route_id} Gmail policy must define positive {field_name}")
        response = adapter_config.get("response")
        response_fields = _validate_bounded_response_profiles(route_id, response, "Gmail")
        assert isinstance(response, dict)
        if response.get("validateInternalDate") is not True:
            raise PolicyBundleError(f"route {route_id} Gmail policy must validate response internalDate")
        if not isinstance(response.get("validateListByMetadataFetch"), bool):
            raise PolicyBundleError(
                f"route {route_id} Gmail policy must explicitly configure list metadata age proof"
            )
        if response.get("onViolation") != "block":
            raise PolicyBundleError(f"route {route_id} Gmail response violations must block")
        message_header_names = response.get("allowedMessageHeaderNames")
        if "payload.headers" in response_fields:
            if (
                not isinstance(message_header_names, list)
                or not message_header_names
                or len(message_header_names) > 64
                or any(
                    not isinstance(name, str)
                    or not name
                    or len(name) > 128
                    or ":" in name
                    or "\r" in name
                    or "\n" in name
                    for name in message_header_names
                )
                or len({name.lower() for name in message_header_names}) != len(message_header_names)
            ):
                raise PolicyBundleError(
                    f"route {route_id} Gmail payload.headers requires 1-64 unique allowedMessageHeaderNames"
                )
        elif "allowedMessageHeaderNames" in response:
            raise PolicyBundleError(
                f"route {route_id} Gmail allowedMessageHeaderNames requires payload.headers in allowedFields"
            )

    if adapter_type == "x.v2":
        if not credential_ref:
            raise PolicyBundleError(f"route {route_id} X policy must bind a credential")
        mode = adapter_config.get("mode")
        allowed_reads = set(adapter_config.get("allowedReadOperations") or [])
        response_mode = str((adapter_config.get("response") or {}).get("mode") or "")
        if mode in {"readOnly", "recentSearchOnly"}:
            if methods != {"GET"}:
                raise PolicyBundleError(f"route {route_id} X read policy may only match GET")
            if not allowed_reads:
                raise PolicyBundleError(f"route {route_id} X read policy must allow explicit read operations")
            if mode == "recentSearchOnly" and allowed_reads != {"search.read"}:
                raise PolicyBundleError(
                    f"route {route_id} X recent-search policy may only allow search.read"
                )
            if mode == "recentSearchOnly" and not set(paths).issubset(X_V2_RECENT_SEARCH_PATHS):
                raise PolicyBundleError(
                    f"route {route_id} X recent-search policy may only match exact recent-search endpoints"
                )
            if "streams.read" in allowed_reads:
                if allowed_reads != {"streams.read"} or response_mode != "stream":
                    raise PolicyBundleError(
                        f"route {route_id} X streams require a dedicated stream-only route"
                    )
            elif response_mode == "stream":
                raise PolicyBundleError(
                    f"route {route_id} X bounded reads cannot use an unvalidated stream response"
                )
        elif mode == "controlledWrite":
            if methods != {"POST"} or set(paths) != {"/2/tweets"}:
                raise PolicyBundleError(
                    f"route {route_id} controlled X writes currently support only POST /2/tweets"
                )
            operation_policies = [
                set(constraint.get("allowedOperations") or [])
                for constraint in constraints
                if constraint.get("type") == "operationPolicy"
            ]
            if {"tweets.write"} not in operation_policies:
                raise PolicyBundleError(
                    f"route {route_id} controlled X post writes require a tweets.write operation allowlist"
                )
            if not any(constraint.get("type") == "jsonBody" for constraint in constraints):
                raise PolicyBundleError(
                    f"route {route_id} controlled X post writes require an explicit JSON body policy"
                )
            if response_mode == "stream":
                raise PolicyBundleError(f"route {route_id} controlled X writes cannot stream responses")

    if adapter_type == "npm.registry":
        operations = set(adapter_config.get("operations") or [])
        write_operations = operations.intersection(NPM_WRITE_OPERATIONS)
        response = adapter_config.get("response")
        _validate_bounded_response_profiles(route_id, response, "npm")
        if not write_operations:
            return
        assert isinstance(response, dict)
        if response.get("mode") != "json":
            raise PolicyBundleError(f"route {route_id} npm writes require a bounded json success response")
        authn = ((jit.get("approvers") or {}).get("authn") or {}) if isinstance(jit, dict) else {}
        authenticator_classes = set(authn.get("allowedAuthenticatorClasses") or [])
        if (
            jit.get("required") is not True
            or jit.get("mode") != "perOperation"
            or jit.get("maxUses") != 1
            or jit.get("consumeOn") != "forwardStart"
            or authn.get("webauthnRequired") is not True
            or authn.get("userVerification") != "required"
            or authn.get("requireHardwareAttestation") is not True
            or not authenticator_classes
            or not authenticator_classes.issubset({"yubikey", "hardware"})
        ):
            raise PolicyBundleError(
                f"route {route_id} npm writes require one-use, hardware-attested WebAuthn JIT"
            )


def compile_policy_bundle(raw: dict[str, Any], *, verify_signature: bool = False, validate_schema: bool = False) -> PolicySnapshot:
    if validate_schema:
        validate_policy_schema(raw)
    if verify_signature:
        verify_policy_signature(raw)
    if raw.get("apiVersion") != "serverware.policy/v1":
        raise PolicyBundleError("apiVersion must be serverware.policy/v1")
    if raw.get("kind") != "PolicyBundle":
        raise PolicyBundleError("kind must be PolicyBundle")

    metadata = raw.get("metadata") or {}
    if "validFrom" in metadata:
        raise PolicyBundleError("metadata.validFrom is unsupported until activation-time enforcement is implemented")
    defaults = raw.get("defaults")
    if not isinstance(defaults, dict):
        raise PolicyBundleError("policy bundle must define explicit fail-closed defaults")
    for name, expected in FAIL_CLOSED_DEFAULTS.items():
        if defaults.get(name) != expected:
            raise PolicyBundleError(f"defaults.{name} must be {expected}")

    principal_items = raw.get("principals") or []
    credential_items = raw.get("credentials") or []
    route_items = raw.get("routes") or []
    if not principal_items:
        raise PolicyBundleError("at least one principal is required")

    principals: dict[str, PrincipalPolicy] = {}
    for item in principal_items:
        principal_id = item["id"]
        if principal_id in principals:
            raise PolicyBundleError(f"duplicate principal: {principal_id}")
        if "spiffeIds" in item:
            raise PolicyBundleError(
                f"principal {principal_id} uses unsupported spiffeIds; workload identity evidence is not implemented"
            )
        source_cidrs = tuple(item.get("sourceCidrs") or ())
        required_headers = dict(item.get("requiredHeaders") or {})
        proxy_authorization = ProxyAuthorizationPolicy.from_raw(item.get("proxyAuthorization"))
        if not (source_cidrs or required_headers or proxy_authorization):
            raise PolicyBundleError(f"principal {principal_id} must define at least one enforceable identity selector")
        try:
            for cidr in source_cidrs:
                ipaddress.ip_network(cidr, strict=False)
            if proxy_authorization:
                proxy_authorization.networks
        except ValueError as exc:
            raise PolicyBundleError(f"principal {principal_id} contains an invalid source CIDR") from exc
        principals[principal_id] = PrincipalPolicy(
            id=principal_id,
            source_cidrs=source_cidrs,
            required_headers=required_headers,
            proxy_authorization=proxy_authorization,
        )

    credentials: dict[str, CredentialPolicy] = {}
    for item in credential_items:
        credential_id = item["id"]
        if credential_id in credentials:
            raise PolicyBundleError(f"duplicate credential: {credential_id}")
        provider = str(item.get("provider", "generic")).strip()
        provider_subject = item.get("providerSubject")
        if provider_subject is not None:
            if (
                not isinstance(provider_subject, str)
                or not provider_subject
                or provider_subject != provider_subject.strip()
                or len(provider_subject) > 512
                or any(ord(character) < 32 or ord(character) == 127 for character in provider_subject)
            ):
                raise PolicyBundleError(f"credential {credential_id} has an invalid provider subject")
            if provider in {"", "generic"}:
                raise PolicyBundleError(f"credential {credential_id} provider subject requires a concrete provider")
        if provider.lower() in MANAGED_OAUTH_PROVIDERS and provider_subject is None:
            raise PolicyBundleError(f"OAuth credential {credential_id} requires a signed provider subject")
        injection = _validate_credential_injection(
            credential_id,
            item.get("injection"),
        )
        _validate_managed_oauth_injection(credential_id, provider, injection)
        credentials[credential_id] = CredentialPolicy(
            id=credential_id,
            provider=provider,
            provider_subject=provider_subject,
            scopes=tuple(item.get("scopes") or ()),
            injection=injection,
        )

    routes: list[RoutePolicy] = []
    seen_routes: set[str] = set()
    for item in route_items:
        route_id = item["id"]
        if route_id in seen_routes:
            raise PolicyBundleError(f"duplicate route: {route_id}")
        seen_routes.add(route_id)

        match = item.get("match") or {}
        methods = frozenset(method.upper() for method in (match.get("methods") or []))
        if not methods:
            raise PolicyBundleError(f"route {route_id} must define methods")
        paths = tuple(match.get("paths") or ())
        if not paths:
            raise PolicyBundleError(f"route {route_id} must define paths")
        adapter = item.get("adapter") or {"type": "generic.rest", "config": {}}
        adapter_type = adapter.get("type", "generic.rest")
        adapter_config = dict(adapter.get("config") or {})
        if adapter_type not in SUPPORTED_ADAPTERS:
            raise PolicyBundleError(f"route {route_id} uses unsupported adapter {adapter_type}")
        if adapter_type != "gmail.v1":
            response_config = adapter_config.get("response")
            if not isinstance(response_config, dict):
                raise PolicyBundleError(f"route {route_id} response policy missing")
            response_mode = response_config.get("mode")
            supported_modes = SUPPORTED_RESPONSE_MODES if adapter_type == "generic.rest" else BUFFERED_RESPONSE_MODES | {"stream"}
            if not isinstance(response_mode, str) or response_mode not in supported_modes:
                raise PolicyBundleError(f"route {route_id} response mode {response_mode!r} is unsupported")
            max_response_bytes = response_config.get("maxBodyBytes")
            if (
                isinstance(max_response_bytes, bool)
                or not isinstance(max_response_bytes, int)
                or max_response_bytes < 0
                or max_response_bytes > 16 * 1024 * 1024
            ):
                raise PolicyBundleError(
                    f"route {route_id} response maxBodyBytes must be an integer between 0 and 16777216"
                )
            if adapter_type not in {"npm.registry"}:
                _validate_optional_response_release_contract(
                    route_id, response_config, adapter_type
                )
            if (
                response_mode in STREAMING_RESPONSE_MODES
                and response_config.get("allowedHeaders")
            ):
                raise PolicyBundleError(
                    f"route {route_id} streaming responses cannot release upstream headers"
                )
        credential_ref = item.get("credentialRef")
        if credential_ref and credential_ref not in credentials:
            raise PolicyBundleError(f"route {route_id} references unknown credential {credential_ref}")
        request_mode = str(((adapter_config.get("request") or {}).get("bodyMode") or ""))
        response_mode = str(((adapter_config.get("response") or {}).get("mode") or ""))
        if credential_ref and response_mode in {"any", "stream"}:
            raise PolicyBundleError(
                f"route {route_id} credential-bearing responses require projection or structured validation"
            )
        if (
            credential_ref
            and request_mode in STREAMING_RESPONSE_MODES
            and not methods.issubset({"GET", "HEAD", "OPTIONS"})
        ):
            raise PolicyBundleError(
                f"route {route_id} credential-bearing mutating request streams must buffer before forwarding"
            )
        if adapter_type == "generic.rest":
            request_config = adapter_config.get("request") or {}
            response_config = adapter_config.get("response") or {}
            if not request_config or not response_config:
                raise PolicyBundleError(
                    f"route {route_id} uses generic.rest and must define request and response schemas"
                )
            missing_request = sorted(
                key for key in ("allowedHeaders", "allowedQueryKeys", "bodyMode", "maxBodyBytes") if key not in request_config
            )
            missing_response = sorted(key for key in ("mode", "maxBodyBytes") if key not in response_config)
            if missing_request or missing_response:
                raise PolicyBundleError(
                    f"route {route_id} generic.rest policy is missing explicit controls: "
                    f"request={missing_request} response={missing_response}"
                )
            raw_allowed_headers = request_config.get("allowedHeaders")
            if not isinstance(raw_allowed_headers, list) or any(
                not isinstance(header, str)
                or not header
                or len(header) > 128
                or HTTP_HEADER_NAME_RE.fullmatch(header) is None
                for header in raw_allowed_headers
            ):
                raise PolicyBundleError(
                    f"route {route_id} generic.rest allowedHeaders must contain HTTP field names"
                )
            allowed_headers = [header.lower() for header in raw_allowed_headers]
            if len(allowed_headers) != len(set(allowed_headers)):
                raise PolicyBundleError(
                    f"route {route_id} generic.rest allowedHeaders must be unique after normalization"
                )
            allowed_header_set = set(allowed_headers)
            forbidden_headers = sorted(FORBIDDEN_AGENT_CREDENTIAL_HEADERS.intersection(allowed_header_set))
            if forbidden_headers:
                raise PolicyBundleError(
                    f"route {route_id} generic.rest allows credential headers supplied by the agent: {forbidden_headers}"
                )
            required_headers = _validate_generic_required_headers(
                route_id,
                request_config,
                allowed_header_set,
            )
            raw_allowed_query = request_config.get("allowedQueryKeys")
            if not isinstance(raw_allowed_query, list) or any(
                not isinstance(key, str) or not key or len(key) > 256 for key in raw_allowed_query
            ):
                raise PolicyBundleError(
                    f"route {route_id} generic.rest allowedQueryKeys must contain bounded strings"
                )
            if len(raw_allowed_query) != len(set(raw_allowed_query)):
                raise PolicyBundleError(
                    f"route {route_id} generic.rest allowedQueryKeys must be unique"
                )
            if credential_ref:
                target = credential_injection_target(credentials[credential_ref].injection)
                if target is not None:
                    location, name = target
                    if location == "header" and (name in allowed_header_set or name in required_headers):
                        raise PolicyBundleError(
                            f"route {route_id} generic.rest agent header {name} collides with credential injection"
                        )
                    if location == "query" and name in set(raw_allowed_query):
                        raise PolicyBundleError(
                            f"route {route_id} generic.rest agent query key {name} collides with credential injection"
                        )
        route_principals = tuple(item.get("principals") or ())
        for principal_id in route_principals:
            if principal_id != "*" and principal_id not in principals:
                raise PolicyBundleError(f"route {route_id} references unknown principal {principal_id}")
        jit = dict(item.get("jit") or {})
        if jit:
            for required_key in ("mode", "ttlSeconds", "maxUses", "consumeOn", "binding", "approvers"):
                if required_key not in jit:
                    raise PolicyBundleError(f"route {route_id} JIT policy must define {required_key}")
            if jit.get("mode") != "perOperation":
                raise PolicyBundleError(f"route {route_id} JIT mode must be perOperation")
            if jit.get("consumeOn") != "forwardStart":
                raise PolicyBundleError(f"route {route_id} JIT consumeOn must be forwardStart")
            binding = jit.get("binding") or {}
            if binding.get("type") not in {"requestDigest", "operationDigest"}:
                raise PolicyBundleError(
                    f"route {route_id} JIT binding must use requestDigest or operationDigest"
                )
            binding_fields = set(binding.get("fields") or [])
            missing_fields = sorted(REQUIRED_JIT_BINDING_FIELDS - binding_fields)
            if missing_fields:
                raise PolicyBundleError(
                    f"route {route_id} JIT binding is missing required fields: {', '.join(missing_fields)}"
                )
            approvers = jit.get("approvers") or {}
            if int(approvers.get("quorum", 0)) != 1:
                raise PolicyBundleError(f"route {route_id} JIT approver quorum must be 1")
            if not approvers.get("users"):
                raise PolicyBundleError(f"route {route_id} JIT policy must define allowed approver users")
            authn = approvers.get("authn") or {}
            if authn.get("webauthnRequired") and not authn.get("allowedAuthenticatorClasses"):
                raise PolicyBundleError(f"route {route_id} WebAuthn JIT policy must define allowed authenticator classes")
        constraints = _validate_constraints(route_id, item.get("constraints"))
        _validate_provider_account_rate_limits(
            route_id,
            constraints,
            credentials.get(credential_ref) if credential_ref else None,
        )
        _validate_adapter_security_invariants(
            route_id,
            adapter_type,
            adapter_config,
            credential_ref,
            jit,
            methods,
            paths,
            constraints,
        )
        response_mode = str((adapter_config.get("response") or {}).get("mode") or "")
        if response_mode in STREAMING_RESPONSE_MODES and any(
            constraint.get("phase", "request") == "response" for constraint in constraints
        ):
            raise PolicyBundleError(
                f"route {route_id} cannot stream a response that requires whole-response constraint validation"
            )

        routes.append(
            RoutePolicy(
                id=route_id,
                principals=route_principals,
                scheme=(match.get("scheme") or "https").lower(),
                host=(match["host"]).lower().rstrip("."),
                port=int(match.get("port", 443)),
                methods=methods,
                path_templates=paths,
                path_regexes=tuple(_path_template_to_regex(path) for path in paths),
                credential_ref=credential_ref,
                adapter_type=adapter_type,
                adapter_config=adapter_config,
                constraints=constraints,
                jit=jit,
            )
        )

    for index, left in enumerate(routes):
        for right in routes[index + 1 :]:
            if (left.scheme, left.host, left.port) != (right.scheme, right.host, right.port):
                continue
            if not left.methods.intersection(right.methods):
                continue
            if not set(left.principals).intersection(right.principals) and "*" not in left.principals and "*" not in right.principals:
                continue
            for left_path in left.path_templates:
                for right_path in right.path_templates:
                    if _path_shape(left_path) == _path_shape(right_path) and _path_specificity(left_path) == _path_specificity(right_path):
                        raise PolicyBundleError(
                            f"routes {left.id} and {right.id} have ambiguous path templates {left_path} and {right_path}"
                        )
    routes.sort(key=lambda route: route.id)
    return PolicySnapshot(
        raw=raw,
        hash=policy_hash(raw),
        principals=principals,
        credentials=credentials,
        routes=tuple(routes),
    )


def get_policy_snapshot() -> PolicySnapshot | None:
    global _SNAPSHOT_CACHE
    path = POLICY_BUNDLE_PATH
    if not path.exists():
        _SNAPSHOT_CACHE = (None, None)
        return None
    mtime = path.stat().st_mtime
    cached_mtime, cached_snapshot = _SNAPSHOT_CACHE
    if cached_snapshot and cached_mtime == mtime:
        return cached_snapshot
    try:
        snapshot = compile_policy_bundle(_load_raw_policy(path), verify_signature=True, validate_schema=True)
    except (OSError, ValueError, TypeError, json.JSONDecodeError, PolicyBundleError):
        _SNAPSHOT_CACHE = (mtime, None)
        return None
    _SNAPSHOT_CACHE = (mtime, snapshot)
    return snapshot


def enforce_policy_high_water(snapshot: PolicySnapshot) -> dict[str, Any]:
    metadata = snapshot.raw.get("metadata")
    if not isinstance(metadata, dict):
        raise PolicyBundleError("policy metadata is missing")
    policy_id = metadata.get("id")
    sequence = metadata.get("sequence")
    rollback_epoch = metadata.get("rollbackEpoch")
    if not isinstance(policy_id, str) or not policy_id:
        raise PolicyBundleError("policy metadata id is invalid")
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        raise PolicyBundleError("policy metadata sequence is invalid")
    if not isinstance(rollback_epoch, int) or isinstance(rollback_epoch, bool):
        raise PolicyBundleError("policy metadata rollbackEpoch is invalid")
    if sequence < POLICY_MIN_SEQUENCE:
        raise PolicyBundleError(
            f"policy sequence {sequence} is below configured floor {POLICY_MIN_SEQUENCE}"
        )
    if rollback_epoch < POLICY_MIN_ROLLBACK_EPOCH:
        raise PolicyBundleError(
            "policy rollbackEpoch "
            f"{rollback_epoch} is below configured floor {POLICY_MIN_ROLLBACK_EPOCH}"
        )
    from serverware import db

    try:
        return db.advance_policy_high_water(
            policy_id=policy_id,
            sequence=sequence,
            rollback_epoch=rollback_epoch,
            policy_hash=snapshot.hash,
        )
    except db.MetadataStoreError as exc:
        raise PolicyBundleError(f"policy rollback protection rejected bundle: {exc}") from exc


def _atomic_write_policy(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def write_policy_bundle(
    raw: dict[str, Any],
    path: Path = POLICY_BUNDLE_PATH,
    *,
    enforce_high_water: bool = False,
) -> PolicySnapshot:
    ensure_data_dirs()
    signed = sign_policy_bundle(raw)
    snapshot = compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
    if enforce_high_water:
        enforce_policy_high_water(snapshot)
    _atomic_write_policy(path, json.dumps(signed, indent=2, sort_keys=True) + "\n")
    global _SNAPSHOT_CACHE
    _SNAPSHOT_CACHE = (path.stat().st_mtime, snapshot)
    return snapshot


def demo_policy_bundle(credential_id: str = "cred-demo-bearer") -> dict[str, Any]:
    proxy_token_sha256 = "sha256:" + hashlib.sha256(b"demo-agent-proxy-token").hexdigest()
    bound_proxy_token_sha256 = "sha256:" + hashlib.sha256(b"demo-bound-proxy-token").hexdigest()
    return {
        "apiVersion": "serverware.policy/v1",
        "kind": "PolicyBundle",
        "metadata": {
            "id": "serverware-demo",
            "sequence": 1,
            "rollbackEpoch": 1,
        },
        "defaults": {
            "action": "deny",
            "failMode": "closed",
            "unknownHosts": "block",
            "unknownPaths": "block",
            "validationFailure": "block",
        },
        "principals": [
            {
                "id": "agent:demo",
                "sourceCidrs": ["0.0.0.0/0", "::/0"],
                "requiredHeaders": {"X-Serverware-Agent": "demo-agent"},
            },
            {
                "id": "agent:demo-proxy-token",
                "sourceCidrs": ["0.0.0.0/0", "::/0"],
                "requiredHeaders": {"X-Serverware-Agent": "demo-token-agent"},
                "proxyAuthorization": {
                    "scheme": "Bearer",
                    "tokenId": "demo-sidecar-token",
                    "tokenSha256": proxy_token_sha256,
                    "sourceCidrs": ["0.0.0.0/0", "::/0"],
                    "expiresAtEpochMs": 4102444800000,
                },
            },
            {
                "id": "agent:demo-source-bound-proxy-token",
                "sourceCidrs": ["0.0.0.0/0", "::/0"],
                "requiredHeaders": {"X-Serverware-Agent": "demo-bound-agent"},
                "proxyAuthorization": {
                    "scheme": "Bearer",
                    "tokenId": "demo-bound-sidecar-token",
                    "tokenSha256": bound_proxy_token_sha256,
                    "sourceCidrs": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"],
                    "expiresAtEpochMs": 4102444800000,
                },
            }
        ],
        "credentials": [
            {
                "id": credential_id,
                "provider": "demo",
                "scopes": ["demo"],
                "injection": {"type": "bearer", "header": "Authorization"},
            }
        ],
        "routes": [
            {
                "id": "demo.echo",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["GET", "POST"],
                    "paths": ["/echo"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": ["reflectCredential"],
                            "allowedHeaders": ["accept", "content-type", "user-agent"],
                            "bodyMode": "any",
                            "maxBodyBytes": 65536,
                        },
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": [
                                "method",
                                "path",
                                "query",
                                "authorization_present",
                                "authorization_scheme",
                                "credential_marker",
                                "credential_reflection",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["GET"],
                    "paths": ["/stream-bytes"],
                },
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": ["chunks", "chunkSize", "reflectCredential"],
                            "allowedHeaders": ["accept", "user-agent"],
                            "bodyMode": "none",
                            "maxBodyBytes": 0,
                        },
                        "response": {
                            "mode": "stream",
                            "maxBodyBytes": 1048576,
                        },
                    },
                },
            },
            {
                "id": "demo.upload.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/upload-bytes"],
                },
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "content-type", "user-agent"],
                            "bodyMode": "stream",
                            "maxBodyBytes": 1048576,
                        },
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": [
                                "method",
                                "path",
                                "authorization_present",
                                "authorization_scheme",
                                "bytes",
                                "sha256",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.jsonl.redact.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/jsonl-redact"],
                },
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "content-type", "user-agent"],
                            "allowedFields": ["index", "kept", "nested.safe"],
                            "bodyMode": "jsonlStream",
                            "maxBodyBytes": 1048576,
                            "maxLineBytes": 8192,
                        },
                        "response": {
                            "mode": "jsonlStream",
                            "maxBodyBytes": 1048576,
                            "maxLineBytes": 8192,
                            "allowedFields": [
                                "index",
                                "kept",
                                "nested.safe",
                                "sawSecret",
                                "authorization_present",
                                "authorization_scheme",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.json.array.redact.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/json-array-redact"],
                },
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "content-type", "user-agent"],
                            "allowedFields": ["index", "kept", "nested.safe"],
                            "bodyMode": "jsonArrayStream",
                            "maxBodyBytes": 1048576,
                            "maxItemBytes": 8192,
                        },
                        "response": {
                            "mode": "jsonArrayStream",
                            "maxBodyBytes": 1048576,
                            "maxItemBytes": 8192,
                            "allowedFields": [
                                "index",
                                "kept",
                                "nested.safe",
                                "sawSecret",
                                "authorization_present",
                                "authorization_scheme",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.json.sse.redact.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/json-sse-redact"],
                },
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "content-type", "user-agent"],
                            "allowedFields": ["index", "kept", "nested.safe"],
                            "bodyMode": "jsonSseStream",
                            "maxBodyBytes": 1048576,
                            "maxLineBytes": 8192,
                            "maxEventBytes": 8192,
                        },
                        "response": {
                            "mode": "jsonSseStream",
                            "maxBodyBytes": 1048576,
                            "maxLineBytes": 8192,
                            "maxEventBytes": 8192,
                            "allowedFields": [
                                "index",
                                "kept",
                                "nested.safe",
                                "sawSecret",
                                "authorization_present",
                                "authorization_scheme",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.json.nested.redact.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/json-nested-redact"],
                },
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "content-type", "user-agent"],
                            "allowedFields": [
                                "requestId",
                                "profile.email",
                                "profile.settings.theme",
                                "items.id",
                                "items.details.safe",
                                "audit.trace",
                            ],
                            "bodyMode": "jsonNestedStream",
                            "maxBodyBytes": 1048576,
                            "maxNestedBytes": 262144,
                        },
                        "response": {
                            "mode": "jsonNestedStream",
                            "maxBodyBytes": 1048576,
                            "maxNestedBytes": 262144,
                            "allowedFields": [
                                "requestId",
                                "profile.email",
                                "profile.settings.theme",
                                "items.id",
                                "items.details.safe",
                                "audit.trace",
                                "sawSecret",
                                "authorization_present",
                                "authorization_scheme",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.form.urlencoded.redact.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/form-redact"],
                },
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "content-type", "user-agent"],
                            "allowedFields": ["kept", "safe"],
                            "bodyMode": "formUrlencodedStream",
                            "maxBodyBytes": 1048576,
                            "maxPairBytes": 8192,
                        },
                        "response": {
                            "mode": "formUrlencodedStream",
                            "maxBodyBytes": 1048576,
                            "maxPairBytes": 8192,
                            "allowedFields": [
                                "kept",
                                "safe",
                                "sawSecret",
                                "authorization_present",
                                "authorization_scheme",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.csv.redact.stream",
                "principals": ["agent:demo", "agent:demo-proxy-token", "agent:demo-source-bound-proxy-token"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/csv-redact"],
                },
                "adapter": {
                    "type": "generic.rest",
                    "config": {
                        "request": {
                            "allowedQueryKeys": [],
                            "allowedHeaders": ["accept", "content-type", "user-agent"],
                            "allowedFields": ["id", "public", "safe_note"],
                            "bodyMode": "csvStream",
                            "maxBodyBytes": 1048576,
                            "maxRecordBytes": 8192,
                        },
                        "response": {
                            "mode": "csvStream",
                            "maxBodyBytes": 1048576,
                            "maxRecordBytes": 8192,
                            "allowedFields": [
                                "id",
                                "public",
                                "safe_note",
                                "sawSecret",
                                "authorization_present",
                                "authorization_scheme",
                            ],
                        },
                    },
                },
            },
            {
                "id": "demo.gmail.recent",
                "principals": ["agent:demo"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["GET"],
                    "paths": [
                        "/gmail/v1/users/{user}/messages",
                        "/gmail/v1/users/{user}/messages/{message_id}",
                    ],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "gmail.v1",
                    "config": {
                        "maxAgeDays": 30,
                        "maxResults": 10,
                        "forceQuery": True,
                        "allowMessageGetOnlyFromPriorSearch": True,
                        "cacheTtlSeconds": 1800,
                        "denyEquivalentEndpoints": ["threads", "history", "attachments", "imap"],
                        "response": {
                            "validateInternalDate": True,
                            "validateListByMetadataFetch": True,
                            "maxBodyBytes": 1048576,
                            "allowedFields": [
                                "id",
                                "threadId",
                                "labelIds",
                                "snippet",
                                "internalDate",
                                "payload.headers",
                            ],
                            "allowedHeaders": [],
                            "allowedMessageHeaderNames": ["From", "Subject", "Date"],
                            "error": {
                                "mode": "json",
                                "maxBodyBytes": 65536,
                                "allowedFields": [
                                    "error.code",
                                    "error.status",
                                    "error.message",
                                    "error.errors.reason",
                                    "error.errors.domain",
                                ],
                                "allowedHeaders": ["retry-after", "www-authenticate"],
                                "onInvalid": "block",
                            },
                            "onViolation": "block",
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "gmail-list-response-30d",
                        "type": "responseDateWindow",
                        "phase": "response",
                        "description": "List responses may only release message metadata proven to be inside the last 30 days.",
                        "operations": ["gmail.messages.list"],
                        "items": ["messages"],
                        "dateFields": ["internalDate"],
                        "formats": ["epochMillis"],
                        "maxAgeDays": 30,
                        "required": True,
                    },
                ],
            },
            {
                "id": "demo.x.tweet.one_per_day",
                "principals": ["agent:demo"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["POST"],
                    "paths": ["/2/tweets"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "x.v2",
                    "config": {
                        "mode": "controlledWrite",
                        "blockWrites": False,
                        "appIds": ["demo-x-app"],
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": [
                                "data.id",
                                "data.text",
                                "authorization_present",
                                "authorization_scheme",
                            ],
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "x-only-tweet-create",
                        "type": "operationPolicy",
                        "description": "This controlled-write route can only use the tweet-create operation.",
                        "allowedOperations": ["tweets.write"],
                    },
                    {
                        "id": "x-one-tweet-per-day",
                        "type": "rateLimit",
                        "description": "The Docker fixture can publish at most one tweet per day for this principal and credential.",
                        "max": 1,
                        "windowSeconds": 86400,
                        "store": "shared",
                        "key": {
                            "scope": ["principal", "credential", "route", "operation"],
                        },
                    },
                    {
                        "id": "x-tweet-body-shape",
                        "type": "jsonBody",
                        "description": "Tweets must be plain text posts with no media, polls, or hidden write side effects.",
                        "contentTypes": ["application/json"],
                        "allowedFields": ["text", "reply_settings"],
                        "requiredFields": ["text"],
                        "deniedFields": ["media", "poll", "direct_message_deep_link", "for_super_followers_only"],
                        "fields": {
                            "text": {"type": "string", "minLength": 1, "maxLength": 280},
                            "reply_settings": {"type": "string", "enum": ["following", "mentionedUsers"]},
                        },
                    },
                ],
            },
            {
                "id": "demo.x.search.recent",
                "principals": ["agent:demo"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["GET"],
                    "paths": ["/2/tweets/search/recent"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "x.v2",
                    "config": {
                        "mode": "recentSearchOnly",
                        "blockWrites": True,
                        "appIds": ["demo-x-app"],
                        "allowedReadOperations": ["search.read"],
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": [
                                "data.id",
                                "data.text",
                                "data.created_at",
                                "meta.result_count",
                                "authorization_present",
                                "authorization_scheme",
                            ],
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "x-search-start-time-7d",
                        "type": "queryDateWindow",
                        "description": "Search cursors cannot ask for tweets older than seven days.",
                        "parameters": ["start_time", "end_time"],
                        "maxAgeDays": 7,
                        "formats": ["rfc3339", "date"],
                        "required": False,
                    },
                    {
                        "id": "x-search-result-cap",
                        "type": "queryNumericBounds",
                        "description": "Result pages stay bounded even when SDK defaults are overridden.",
                        "parameters": ["max_results"],
                        "min": 1,
                        "max": 100,
                        "integer": True,
                    },
                    {
                        "id": "x-search-response-7d",
                        "type": "responseDateWindow",
                        "phase": "response",
                        "description": "The upstream response must not contain tweets outside the same seven-day window.",
                        "items": ["data"],
                        "dateFields": ["created_at"],
                        "formats": ["rfc3339", "date"],
                        "maxAgeDays": 7,
                        "required": True,
                    },
                ],
            },
            {
                "id": "demo.x.readonly",
                "principals": ["agent:demo"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["GET"],
                    "paths": ["/2/**"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "x.v2",
                    "config": {
                        "mode": "readOnly",
                        "blockWrites": True,
                        "appIds": ["demo-x-app"],
                        "allowedReadOperations": sorted(X_V2_BOUNDED_READ_OPERATIONS),
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 1048576,
                            "allowedFields": [
                                "data",
                                "includes",
                                "meta",
                                "errors",
                                "title",
                                "detail",
                                "type",
                                "status",
                                "authorization_present",
                                "authorization_scheme",
                            ],
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "x-readonly-operation-allowlist",
                        "type": "operationPolicy",
                        "description": "All currently cataloged bounded X reads are allowed; unknown and streaming endpoints remain blocked.",
                        "allowedOperations": sorted(X_V2_BOUNDED_READ_OPERATIONS),
                    },
                ],
            },
            {
                "id": "demo.npm.publish.jit",
                "principals": ["agent:demo"],
                "match": {
                    "scheme": "https",
                    "host": "demo-upstream",
                    "port": 8443,
                    "methods": ["PUT", "POST"],
                    "paths": ["/npm/{package}", "/npm/-/package/{package}/dist-tags/{tag}"],
                },
                "credentialRef": credential_id,
                "adapter": {
                    "type": "npm.registry",
                    "config": {
                        "operations": ["publish", "distTagWrite"],
                        "response": {
                            "mode": "json",
                            "maxBodyBytes": 65536,
                            "allowedFields": [
                                "package",
                                "published",
                                "tag",
                                "dist_tag_written",
                                "authorization_present",
                                "authorization_scheme",
                            ],
                            "allowedHeaders": [],
                            "error": {
                                "mode": "json",
                                "maxBodyBytes": 65536,
                                "allowedFields": ["error", "reason", "code"],
                                "allowedHeaders": ["retry-after", "www-authenticate"],
                                "onInvalid": "block",
                            },
                        },
                    },
                },
                "constraints": [
                    {
                        "id": "npm-sensitive-operation-allowlist",
                        "type": "operationPolicy",
                        "description": "Only publish and dist-tag writes may reach this JIT-protected npm route.",
                        "allowedOperations": ["npm.publish", "npm.distTagWrite"],
                        "deniedOperations": ["npm.tokenWrite", "npm.metadataWrite"],
                    },
                ],
                "jit": {
                    "required": True,
                    "mode": "perOperation",
                    "ttlSeconds": 30,
                    "maxUses": 1,
                    "consumeOn": "forwardStart",
                    "binding": {
                        "type": "operationDigest",
                        "fields": [
                            "principal",
                            "routeId",
                            "credentialRef",
                            "credentialVersion",
                            "policyHash",
                            "method",
                            "authority",
                            "path",
                            "query",
                            "selectedHeaders",
                            "bodySha256",
                            "packageName",
                            "packageVersion",
                            "tarballIntegrity",
                        ],
                    },
                    "approvers": {
                        "quorum": 1,
                        "users": ["user:demo"],
                        "authn": {
                            "webauthnRequired": True,
                            "userVerification": "required",
                            "allowedAuthenticatorClasses": ["yubikey", "hardware"],
                            "requireHardwareAttestation": True,
                        },
                    },
                },
            },
        ],
    }


def request_url_parts(pretty_url: str) -> tuple[str, str, int, str]:
    parts = urlsplit(pretty_url)
    scheme = parts.scheme or "https"
    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    return scheme, host, port, parts.path or "/"
